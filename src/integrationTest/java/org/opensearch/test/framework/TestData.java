/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.test.framework;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.function.Predicate;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.admin.indices.rollover.RolloverRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.transport.client.Client;

/**
 * Creates set set of randomized documents than can be written to a test index. Especially useful for creating
 * test data for testing DLS/FLS.
 * <p>
 * This class uses several techniques to create realistic situations:
 * <ul>
 *    <li>A fraction of documents is deleted again after having been created.
 *    <li>Uses diverse mapping types and configurations
 *    <li>It creates enough documents to make sure that they are spread around shards (see DEFAULT_DOCUMENT_COUNT below)
 *    <li>Index settings should be defined using the TestIndex class to make sure that there are interesting constellations of shards and replicas
 * </ul>
 */
public class TestData {
    private static final Logger log = LogManager.getLogger(TestData.class);

    public static int DEFAULT_SEED = 1234;
    public static int DEFAULT_DOCUMENT_COUNT = 300;

    public static TestData get() {
        return DEFAULT;
    }

    public static TestData.Builder documentCount(int documentCount) {
        return new Builder().documentCount(documentCount);
    }

    public static final TestData DEFAULT;

    public static final ImmutableSet<String> TEXT_FIELD_NAMES = ImmutableSet.of(
        "attr_text_1",
        "attr_text_1.keyword",
        "attr_text_2",
        "attr_text_2.keyword",
        "attr_text_termvectors",
        "attr_text_termvectors.keyword",
        "attr_text_stored",
        "attr_keyword",
        "attr_keyword_doc_values_disabled",
        "attr_text_doc_values_disabled",
        "attr_text_doc_values_disabled_nullable",
        "attr_object.obj_attr_text_1",
        "attr_object.obj_attr_text_1.keyword",
        "attr_object.obj_attr_text_2",
        "attr_object.obj_attr_text_2.keyword",
        "attr_object.obj_attr_object.obj_obj_attr_text",
        "attr_object.obj_attr_object.obj_obj_attr_text.keyword"
    );

    public static final ImmutableList<String> DEPARTMENTS = ImmutableList.of("dept_a_1", "dept_a_2", "dept_a_3", "dept_b_1", "dept_b_2", "dept_c", "dept_d");

    private static final Cache<Key, TestData> cache;

    static {
        cache = CacheBuilder.newBuilder().softValues().initialCapacity(3).build();
        DEFAULT = documentCount(DEFAULT_DOCUMENT_COUNT).get();
    }

    private String[] ipAddresses;
    private String[] threeWordPhrases;
    private int size;
    private int deletedDocumentCount;
    private int refreshAfter;
    private Map<String, TestDocument> allDocuments;
    private Map<String, TestDocument> retainedDocuments;
    private Map<String, Map<String, TestDocument>> documentsByDepartment;
    private Set<String> deletedDocuments;
    private long subRandomSeed;
    private final String timestampColumn;

    public TestData(int seed, int size, int deletedDocumentCount, int refreshAfter, String timestampColumnName) {
        Random random = new Random(seed);
        this.ipAddresses = createRandomIpAddresses(random);
        this.threeWordPhrases = createRandomThreeWordPhrases(random);
        this.size = size;
        this.deletedDocumentCount = deletedDocumentCount;
        this.refreshAfter = refreshAfter;
        this.subRandomSeed = random.nextLong();
        this.timestampColumn = timestampColumnName;
        this.createTestDocuments(random);
    }

    public void createIndex(Client client, String name, Settings settings) {
        log.info(
            "creating test index "
                + name
                + "; size: "
                + size
                + "; deletedDocumentCount: "
                + deletedDocumentCount
                + "; refreshAfter: "
                + refreshAfter
        );

        String mapping = """
            {
              "_doc": {
                "properties": {
                  "source_ip": {"type": "ip"},
                  "attr_text_stored": {"type": "text", "store": true},
                  "attr_text_doc_values_disabled": {"type": "text", "store": true, "doc_values": false, "norms": false},
                  "attr_text_doc_values_disabled_nullable": {"type": "text", "store": true, "doc_values": false, "norms": false},
                  "attr_keyword": {"type": "keyword"},
                  "attr_keyword_doc_values_disabled": {"type": "keyword", "store": true, "doc_values": false, "norms": false},
                  "attr_boolean": {"type": "boolean"},
                  "attr_long": {"type": "long"},
                  "attr_int": {"type": "integer"},
                  "attr_double": {"type": "double"},
                  "attr_binary": {"type": "binary", "doc_values": true},
                  "attr_geo_point_string": {"type": "geo_point"},
                  "attr_geo_point_string_stored": {"type": "geo_point", "store": true, "doc_values": false},
                  "attr_text_termvectors": {
                    "type": "text",
                    "term_vector": "with_positions_offsets_payloads",
                    "store": true,
                    "analyzer": "standard",
                    "fields": {
                      "keyword": {"type": "keyword"}
                    }
                  }
                }
              }
            }
            """;

        client.admin().indices().create(new CreateIndexRequest(name).settings(settings).mapping(mapping)).actionGet();

        this.putDocuments(client, name, -1);
    }

    /**
     * Writes the documents from this TestData instance to the given index.
     *
     * @param client the client to be used
     * @param name the name of the target index
     * @param rolloverAfter if this is not -1, a rollover operation will be executed for every n documents. This is useful
     *                      for creating several generations of data stream backing indices.
     */
    public void putDocuments(Client client, String name, int rolloverAfter) {
        try {
            Random random = new Random(subRandomSeed);
            long start = System.currentTimeMillis();

            int nextRefresh = (int) Math.floor((random.nextGaussian() * 0.5 + 0.5) * refreshAfter);
            int nextRollover = rolloverAfter != -1 ? rolloverAfter : Integer.MAX_VALUE;
            int i = 0;

            for (Map.Entry<String, TestDocument> entry : allDocuments.entrySet()) {
                String id = entry.getKey();
                TestDocument document = entry.getValue();

                client.index(
                    new IndexRequest(name).source(document.content, XContentType.JSON).id(id).opType(DocWriteRequest.OpType.CREATE)
                ).actionGet();

                if (i > nextRefresh) {
                    client.admin().indices().refresh(new RefreshRequest(name)).actionGet();
                    nextRefresh = (int) Math.floor((random.nextGaussian() * 0.5 + 1) * refreshAfter) + i + 1;
                }

                if (i > nextRollover) {
                    // By using rollover, we make sure that we get several generations of backing indices
                    client.admin().indices().rolloverIndex(new RolloverRequest(name, null));
                    nextRollover += rolloverAfter;
                }

                i++;
            }

            client.admin().indices().refresh(new RefreshRequest(name)).actionGet();

            for (String id : deletedDocuments) {
                client.delete(new DeleteRequest(name, id)).actionGet();
            }

            client.admin().indices().refresh(new RefreshRequest(name)).actionGet();
            log.info("Test index creation finished after " + (System.currentTimeMillis() - start) + " ms");
        } catch (Exception e) {
            throw new RuntimeException("Error while wring test documents to index " + name, e);
        }
    }

    private void createTestDocuments(Random random) {

        Map<String, TestDocument> allDocuments = new HashMap<>(size);

        for (int i = 0; i < size; i++) {
            TestDocument document = randomDocument(random);
            allDocuments.put(document.id, document);
        }

        List<String> createdDocIds = new ArrayList<>(allDocuments.keySet());

        Collections.shuffle(createdDocIds, random);

        Set<String> deletedDocuments = new HashSet<>(deletedDocumentCount);
        Map<String, TestDocument> retainedDocuments = new HashMap<>(allDocuments);

        for (int i = 0; i < deletedDocumentCount; i++) {
            String id = createdDocIds.get(i);
            deletedDocuments.add(id);
            retainedDocuments.remove(id);
        }

        Map<String, Map<String, TestDocument>> documentsByDepartment = new HashMap<>();

        for (Map.Entry<String, TestDocument> entry : retainedDocuments.entrySet()) {
            String dept = (String) entry.getValue().content().get("dept");
            documentsByDepartment.computeIfAbsent(dept, (k) -> new HashMap<>()).put(entry.getKey(), entry.getValue());
        }

        this.allDocuments = Collections.unmodifiableMap(allDocuments);
        this.retainedDocuments = Collections.unmodifiableMap(retainedDocuments);
        this.deletedDocuments = Collections.unmodifiableSet(deletedDocuments);
        this.documentsByDepartment = documentsByDepartment;
    }

    private String[] createRandomIpAddresses(Random random) {
        String[] result = new String[2000];

        for (int i = 0; i < result.length; i++) {
            result[i] = (random.nextInt(10) + 100)
                + "."
                + (random.nextInt(5) + 100)
                + "."
                + random.nextInt(255)
                + "."
                + random.nextInt(255);
        }

        return result;
    }

    private String[] createRandomThreeWordPhrases(Random random) {
        String[] w1 = new String[] {
            "Pretty",
            "Super",
            "Mostly",
            "Reasonably",
            "Jolly",
            "Rather",
            "Surprisingly",
            "Somewhat",
            "Damn",
            "Quite",
            "Fairly",
            "Moderately",
            "Actually",
            "Impressively",
            "Suspiciously",
            "Sufficiently",
            "Suitably" };
        String[] w2 = new String[] {
            "good",
            "fine",
            "nice",
            "decent",
            "alright",
            "cool",
            "great",
            "acceptable",
            "smooth",
            "awesome",
            "good",
            "good",
            "fine",
            "surreal",
            "superb" };
        String[] w3 = new String[] {
            "coffee",
            "pie",
            "hotel",
            "bar",
            "diner",
            "tea",
            "cake",
            "soup",
            "place",
            "present",
            "shrubbery",
            "code",
            "coffee",
            "coffee",
            "coffee" };

        String[] result = new String[2000];
        for (int i = 0; i < result.length; i++) {

            result[i] = w1[random.nextInt(w1.length)] + " " + w2[random.nextInt(w2.length)] + " " + w3[random.nextInt(w3.length)];
        }

        return result;
    }

    private TestDocument randomDocument(Random random) {
        ImmutableMap.Builder<String, Object> builder = ImmutableMap.builder();
        builder.put("source_ip", randomIpAddress(random));
        builder.put("attr_text_1", randomDepartmentName(random));
        builder.put("attr_text_2", randomThreeWordPhrase(random));
        builder.put("attr_text_termvectors", randomThreeWordPhrase(random));
        builder.put("attr_text_stored", randomThreeWordPhrase(random));
        builder.put("attr_text_doc_values_disabled", randomDepartmentName(random));
        if (random.nextBoolean()) {
            builder.put("attr_text_doc_values_disabled_nullable", "value_" + random.nextInt());
        }
        builder.put("attr_keyword", randomDepartmentName(random));
        builder.put("attr_keyword_doc_values_disabled", randomDepartmentName(random));
        builder.put("attr_boolean", random.nextBoolean());
        builder.put("attr_long", random.nextLong());
        builder.put("attr_int", random.nextInt(10000));
        builder.put("attr_double", random.nextDouble());
        builder.put("attr_binary", randomBinaryValue(random));
        builder.put("attr_geo_point_string", randomGeoPointString(random));
        builder.put("attr_geo_point_string_stored", randomGeoPointString(random));
        builder.put(
            "attr_object",
            ImmutableMap.of(
                "obj_attr_text_1",
                randomDepartmentName(random),
                "obj_attr_text_2",
                "value_" + random.nextInt(),
                "obj_attr_long",
                random.nextLong(),
                "obj_attr_object",
                ImmutableMap.of("obj_obj_attr_text", "value_" + random.nextInt())
            )
        );
        if (timestampColumn != null) {
            builder.put(timestampColumn, randomTimestamp(random));
        }

        return new TestDocument(randomId(random), builder.build());
    }

    private String randomIpAddress(Random random) {
        return ipAddresses[random.nextInt(ipAddresses.length)];
    }

    private String randomDepartmentName(Random random) {
        return DEPARTMENTS.get(random.nextInt(DEPARTMENTS.size()));
    }

    private String randomTimestamp(Random random) {
        long epochMillis = random.longs(1, -2857691960709L, 2857691960709L).findFirst().getAsLong();
        return Instant.ofEpochMilli(epochMillis).toString();
    }

    private String randomThreeWordPhrase(Random random) {
        return threeWordPhrases[random.nextInt(threeWordPhrases.length)];
    }

    private String randomBinaryValue(Random random) {
        int r = random.nextInt(12);

        // Create some outstanding values for binary
        if (r == 1 || r == 2 || r == 3) {
            return "top1++vj5H8=";
        } else if (r == 4 || r == 5) {
            return "top2++Mg6Lk=";
        } else if (r == 6) {
            return "top3++H8MaE=";
        } else {
            byte[] binary = new byte[8];
            random.nextBytes(binary);
            return Base64.getEncoder().encodeToString(binary);
        }
    }

    private String randomGeoPointString(Random random) {
        return random.nextDouble(-90, 90) + "," + random.nextDouble(-180, 180);
    }

    private static String randomId(Random random) {
        UUID uuid = new UUID(random.nextLong(), random.nextLong());
        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
        byteBuffer.putLong(uuid.getMostSignificantBits());
        byteBuffer.putLong(uuid.getLeastSignificantBits());
        return Base64.getUrlEncoder().encodeToString(byteBuffer.array()).replace("=", "");
    }

    public int getSize() {
        return size - deletedDocumentCount;
    }

    public int getDeletedDocumentCount() {
        return deletedDocumentCount;
    }

    public Map<String, TestDocument> getRetainedDocuments() {
        return retainedDocuments;
    }

    public TestDocuments documents() {
        return new TestDocuments(this.retainedDocuments);
    }

    public TestDocument anyDocument() {
        return retainedDocuments.values().iterator().next();
    }

    public TestDocument anyDocumentForDepartment(String dept) {
        Map<String, TestDocument> docs = this.documentsByDepartment.get(dept);

        if (docs == null) {
            return null;
        }

        return docs.values().iterator().next();
    }

    private static class Key {

        private final int seed;
        private final int size;
        private final int deletedDocumentCount;
        private final int refreshAfter;
        private final String timestampColumnName;

        public Key(int seed, int size, int deletedDocumentCount, int refreshAfter, String timestampColumnName) {
            super();
            this.seed = seed;
            this.size = size;
            this.deletedDocumentCount = deletedDocumentCount;
            this.refreshAfter = refreshAfter;
            // this.additionalAttributes = additionalAttributes;
            this.timestampColumnName = timestampColumnName;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + deletedDocumentCount;
            result = prime * result + refreshAfter;
            result = prime * result + seed;
            result = prime * result + size;
            result = prime * result + Objects.hashCode(timestampColumnName);
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            Key other = (Key) obj;
            if (deletedDocumentCount != other.deletedDocumentCount) {
                return false;
            }
            if (refreshAfter != other.refreshAfter) {
                return false;
            }
            if (seed != other.seed) {
                return false;
            }
            if (size != other.size) {
                return false;
            }
            if (!Objects.equals(timestampColumnName, other.timestampColumnName)) {
                return false;
            }
            return true;
        }

    }

    public static class Builder {

        private int seed = DEFAULT_SEED;
        private int size = DEFAULT_DOCUMENT_COUNT;
        private int deletedDocumentCount = -1;
        private double deletedDocumentFraction = 0.06;
        private int refreshAfter = -1;
        private int segmentCount = 17;
        private String timestampColumnName;

        public Builder() {
            super();
        }

        public Builder seed(int seed) {
            this.seed = seed;
            return this;
        }

        public Builder documentCount(int size) {
            this.size = size;
            return this;
        }

        public Builder deletedDocumentCount(int deletedDocumentCount) {
            this.deletedDocumentCount = deletedDocumentCount;
            return this;
        }

        public Builder refreshAfter(int refreshAfter) {
            this.refreshAfter = refreshAfter;
            return this;
        }

        public Builder deletedDocumentFraction(double deletedDocumentFraction) {
            this.deletedDocumentFraction = deletedDocumentFraction;
            return this;
        }

        public Builder segmentCount(int segmentCount) {
            this.segmentCount = segmentCount;
            return this;
        }

        public Builder timestampColumnName(String timestampColumnName) {
            this.timestampColumnName = timestampColumnName;
            return this;
        }

        public Key toKey() {
            if (deletedDocumentCount == -1) {
                this.deletedDocumentCount = (int) (this.size * deletedDocumentFraction);
            }

            if (refreshAfter == -1) {
                this.refreshAfter = this.size / this.segmentCount;
            }

            return new Key(seed, size, deletedDocumentCount, refreshAfter, timestampColumnName);
        }

        public TestData get() {
            Key key = toKey();

            try {
                return cache.get(key, () -> new TestData(seed, size, deletedDocumentCount, refreshAfter, timestampColumnName));
            } catch (ExecutionException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static class TestDocuments {
        private final Map<String, TestDocument> documents;
        private final Function<TestDocument, TestDocument> transformerFunction;

        TestDocuments(Map<String, TestDocument> documents) {
            this.documents = documents;
            this.transformerFunction = Function.identity();
        }

        TestDocuments(Map<String, TestDocument> documents, Function<TestDocument, TestDocument> transformerFunction) {
            this.documents = documents;
            this.transformerFunction = transformerFunction;
        }

        public TestDocuments applyTransform(DocumentTransformer transformerFunction) {
            return new TestDocuments(this.documents, this.transformerFunction.andThen(transformerFunction::transform));
        }

        public TestDocuments applyTransform(DocumentTransformer... transformerFunctions) {
            TestDocuments current = this;

            for (DocumentTransformer transformerFunction : transformerFunctions) {
                current = current.applyTransform(transformerFunction);
            }

            return current;
        }

        public TestDocuments where(Predicate<TestDocument> testDocumentPredicate) {
            ImmutableMap.Builder<String, TestDocument> mapBuilder = ImmutableMap.builder();
            for (TestDocument testDocument : this.documents.values()) {
                if (testDocumentPredicate.test(testDocument)) {
                    mapBuilder.put(testDocument.id, testDocument);
                }
            }
            return new TestDocuments(mapBuilder.build(), transformerFunction);
        }

        public Map<Object, Integer> aggregation(String attribute) {
            Map<Object, Integer> result = new HashMap<>();

            for (TestDocument testDocument : this.documents.values()) {
                testDocument = this.transformerFunction.apply(testDocument);
                Object value = testDocument.content.get(attribute);
                if (value != null) {
                    if (attribute.equals("attr_binary") && ((String) value).endsWith("=")) {
                        // In OpenSearch, an aggregation on binary data strips trailing padding chars. Do the same here
                        value = ((String) value).replace("=", "");
                    }

                    result.merge(value, 1, Integer::sum);
                }
            }

            return result;
        }

        public Map<Object, Integer> aggregation(String attribute, int minDocCount) {
            Map<Object, Integer> aggregation = aggregation(attribute);
            Map<Object, Integer> result = new HashMap<>();

            for (Map.Entry<Object, Integer> entry : aggregation.entrySet()) {
                if (entry.getValue() >= minDocCount) {
                    result.put(entry.getKey(), entry.getValue());
                }
            }

            return result;
        }

        public TestDocument get(String id) {
            TestDocument document = documents.get(id);
            if (document != null) {
                return this.transformerFunction.apply(document);
            } else {
                return null;
            }
        }

        public Set<String> allIds() {
            return this.documents.keySet();
        }

        public Map<String, TestData.TestDocument> allDocs() {
            ImmutableMap.Builder<String, TestDocument> mapBuilder = ImmutableMap.builder();
            for (TestDocument testDocument : this.documents.values()) {
                mapBuilder.put(testDocument.id, testDocument);
            }
            return mapBuilder.build();
        }
    }

    public static class TestDocument {
        private final String id;
        private final ImmutableMap<String, ?> content;

        TestDocument(String id, ImmutableMap<String, ?> content) {
            this.id = id;
            this.content = content;
        }

        public String id() {
            return id;
        }

        public Map<String, ?> content() {
            return content;
        }

        public String attrText1() {
            return (String) this.content.get("attr_text_1");
        }

        public String attrText2() {
            return (String) this.content.get("attr_text_2");
        }

        public String attrKeyword() {
            return (String) this.content.get("attr_keyword");
        }

        public String attrKeywordDocValuesDisabled() {
            return (String) this.content.get("attr_keyword_doc_values_disabled");
        }

        public int attrInt() {
            return ((Number) this.content.get("attr_int")).intValue();
        }

        public String sourceIp() {
            return (String) this.content.get("source_ip");
        }

        public String attrGeoPointString() {
            return (String) this.content.get("attr_geo_point_string");
        }

        public Object getAttributeByPath(String... attributes) {
            Object current = this.content;

            for (int i = 0; i < attributes.length; i++) {

                if (current instanceof Map<?, ?> currentObject) {
                    current = currentObject.get(attributes[i]);
                } else {
                    return null;
                }
            }

            return current;
        }

        public TestDocument withoutAttributes(String... attributes) {
            return withoutAttributes(Set.of(attributes));
        }

        public TestDocument withoutAttributes(Set<String> attributesToBeRemoved) {
            Map<String, Object> result = new HashMap<>();
            withoutAttributesRecursively(this.content, result, attributesToBeRemoved, "");
            return new TestDocument(this.id, ImmutableMap.copyOf(result));
        }

        private void withoutAttributesRecursively(
            Map<?, ?> source,
            Map<String, Object> target,
            Set<String> attributesToBeRemoved,
            String attributePrefix
        ) {

            for (Map.Entry<?, ?> sourceEntry : source.entrySet()) {
                String attributeNameWithPath = attributePrefix + sourceEntry.getKey();
                if (attributesToBeRemoved.contains(attributeNameWithPath)) {
                    continue;
                }
                Object sourceValue = sourceEntry.getValue();
                if (sourceValue instanceof Map<?, ?> nestedSourceMap) {
                    Map<String, Object> nestedTargetMap = new HashMap<>();
                    withoutAttributesRecursively(
                        nestedSourceMap,
                        nestedTargetMap,
                        attributesToBeRemoved,
                        attributePrefix + sourceEntry.getKey() + "."
                    );
                    target.put((String) sourceEntry.getKey(), nestedTargetMap);
                } else {
                    target.put((String) sourceEntry.getKey(), sourceValue);
                }
            }
        }

        public TestDocument withOnlyAttributes(String... attributes) {
            Map<String, Object> newContent = new HashMap<>();
            for (String attribute : attributes) {
                if (!attribute.contains(".")) {
                    if (this.content.containsKey(attribute)) {
                        newContent.put(attribute, this.content.get(attribute));
                    }
                } else {
                    addAttributesRecursively(this.content, newContent, attribute.split("\\."), 0);
                }
            }

            return new TestDocument(this.id, ImmutableMap.copyOf(newContent));
        }

        public TestDocument applyTransform(DocumentTransformer transformerFunction) {
            return transformerFunction.transform(this);
        }

        public TestDocument applyFieldTransform(String field, Function<Object, Object> transform) {
            Object currentValue = content.get(field);
            if (currentValue == null) {
                return this;
            }
            Object newValue = transform.apply(currentValue);
            if (newValue == currentValue) {
                return this;
            }

            Map<String, Object> result = new HashMap<>(this.content);
            result.put(field, newValue);

            return new TestDocument(this.id, ImmutableMap.copyOf(result));
        }

        public String getUri(String index) {
            return "/" + index + "/_doc/" + id;
        }

        @SuppressWarnings("unchecked")
        private void addAttributesRecursively(
            Map<?, ?> source,
            Map<String, Object> target,
            String[] attributePath,
            int attributePathPosition
        ) {
            Object sourceObject = source.get(attributePath[attributePathPosition]);
            if (sourceObject == null) {
                return;
            }
            if (attributePathPosition == attributePath.length - 1) {
                target.put(attributePath[attributePathPosition], sourceObject);
            } else if (sourceObject instanceof Map<?, ?> sourceObjectMap) {
                Object nextTarget = target.computeIfAbsent(attributePath[attributePathPosition], k -> new HashMap<>());
                if (nextTarget instanceof Map<?, ?> nextTargetMap) {
                    addAttributesRecursively(
                        sourceObjectMap,
                        (Map<String, Object>) nextTargetMap,
                        attributePath,
                        attributePathPosition + 1
                    );
                }
            }
        }
    }

    @FunctionalInterface
    public interface DocumentTransformer {
        TestDocument transform(TestDocument document);

        static DocumentTransformer withoutAttributes(String... attributes) {
            return (d) -> d.withoutAttributes(attributes);
        }

    }

}
