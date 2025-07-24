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

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.hamcrest.Description;
import org.hamcrest.DiagnosingMatcher;
import org.hamcrest.Matcher;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.test.framework.cluster.TestRestClient;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.spi.json.JacksonJsonProvider;

import static com.fasterxml.jackson.core.JsonToken.START_ARRAY;

public class IndexApiMatchers {

    public static IndexMatcher containsExactly(TestIndexLike... testIndices) {
        Map<String, TestIndexLike> indexNameMap = new HashMap<>();
        boolean containsOpenSearchIndices = false;

        for (TestIndexLike testIndex : testIndices) {
            if (testIndex == OPEN_SEARCH_INDICES) {
                containsOpenSearchIndices = true;
            } else {
                indexNameMap.put(testIndex.name(), testIndex);
            }
        }

        return new ContainsExactlyMatcher(indexNameMap, containsOpenSearchIndices);
    }

    public static IndexMatcher limitedTo(TestIndexLike... testIndices) {
        Map<String, TestIndexLike> indexNameMap = new HashMap<>();

        for (TestIndexLike testIndex : testIndices) {
            indexNameMap.put(testIndex.name(), testIndex);
        }

        return new LimitedToMatcher(indexNameMap);
    }

    public static IndexMatcher unlimited() {
        return new UnlimitedMatcher();
    }

    public static IndexMatcher unlimitedIncludingOpenSearchIndices() {
        return new UnlimitedMatcher(true);
    }

    public static IndexMatcher limitedToNone() {
        return new LimitedToMatcher(Collections.emptyMap());
    }

    /**
     * This returns a magic TestIndexLike object which matches internal OpenSearch indices.
     */
    public static TestIndexLike openSearchIndices() {
        return OPEN_SEARCH_INDICES;
    }

    private final static TestIndexLike OPEN_SEARCH_INDICES = new TestIndexLike() {

        @Override
        public String name() {
            return ".opendistro_security";
        }

        @Override
        public Map<String, TestData.TestDocument> documents() {
            return null;
        }

        @Override
        public Set<String> documentIds() {
            return null;
        }
    };

    public static class ContainsExactlyMatcher extends AbstractIndexMatcher implements IndexMatcher {

        public ContainsExactlyMatcher(Map<String, TestIndexLike> indexNameMap, boolean containsOpenSearchIndices) {
            super(indexNameMap, containsOpenSearchIndices);
        }

        public ContainsExactlyMatcher(
            Map<String, TestIndexLike> indexNameMap,
            boolean containsOpenSearchIndices,
            String jsonPath,
            int statusCodeWhenEmpty
        ) {
            super(indexNameMap, containsOpenSearchIndices, jsonPath, statusCodeWhenEmpty);
        }

        @Override
        public void describeTo(Description description) {
            if (indexNameMap.isEmpty()) {
                if (this.statusCodeWhenEmpty == 200) {
                    description.appendText("a 200 OK response with an empty result set");
                } else {
                    description.appendText("a response with status code " + this.statusCodeWhenEmpty);
                }
            } else {
                description.appendText(
                    "a 200 OK response with exactly the indices " + indexNameMap.keySet().stream().collect(Collectors.joining(", "))
                );
            }
        }

        @Override
        protected boolean matchesImpl(Collection<?> collection, Description mismatchDescription, TestRestClient.HttpResponse response) {

            boolean checkDocs = false;

            // Flatten the collection
            collection = collection.stream()
                .flatMap(e -> e instanceof Collection ? ((Collection<?>) e).stream() : Stream.of(e))
                .collect(Collectors.toSet());

            for (Object object : collection) {
                if (object instanceof String) {
                    checkDocs = false;
                    break;
                } else if (object instanceof Map && ((Map<?, ?>) object).containsKey("_index")) {
                    checkDocs = true;
                    break;
                } else {
                    mismatchDescription.appendText("unexpected value ").appendValue(collection);
                    return false;
                }
            }

            if (checkDocs) {
                return matchesByDocs(collection, mismatchDescription, response);
            } else {
                return matchesByIndices(collection, mismatchDescription, response);
            }
        }

        protected boolean matchesByDocs(Collection<?> collection, Description mismatchDescription, TestRestClient.HttpResponse response) {
            Set<String> pendingDocuments = this.getExpectedDocuments();
            ImmutableSet.Builder<String> seenOpenSearchIndicesBuilder = new ImmutableSet.Builder<String>();

            for (Object object : collection) {
                JsonNode node = DefaultObjectMapper.objectMapper.valueToTree(object);
                String indexName = node.get("_index").asText();

                if (containsOpenSearchIndices && (indexName.startsWith(".opendistro"))) {
                    seenOpenSearchIndicesBuilder.add(indexName);
                    continue;
                }

                TestIndexLike index = indexNameMap.get(indexName);

                if (index == null) {
                    mismatchDescription.appendText("result contains unknown index: ")
                        .appendValue(node.get("_index").asText())
                        .appendText("; expected: ")
                        .appendValue(indexNameMap.keySet())
                        .appendText("\ndocument: ")
                        .appendText(node.toString());
                    mismatchDescription.appendText("\n\n").appendValue(formatResponse(response));

                    return false;
                }

                TestData.TestDocument document = index.documents().get(node.get("_id").asText());

                if (document == null) {
                    mismatchDescription.appendText("result contains unknown document id ")
                        .appendValue(node.get("_id").asText())
                        .appendText(" for index ")
                        .appendValue(node.get("_index").asText())
                        .appendText("\ndocument: ")
                        .appendText(node.toString());
                    mismatchDescription.appendText("\n\n").appendValue(formatResponse(response));

                    return false;
                }

                Map source = DefaultObjectMapper.objectMapper.convertValue(node.get("_source"), Map.class);
                if (!document.content().equals(source)) {
                    mismatchDescription.appendText("result document ")
                        .appendValue(node.get("_id").asText())
                        .appendText(" in index ")
                        .appendValue(node.get("_index").asText())
                        .appendText(" does not match expected document:\n")
                        .appendText(node.get("_source").toString())
                        .appendText("\n")
                        .appendText(DefaultObjectMapper.objectMapper.valueToTree(document.content()).toString());
                    mismatchDescription.appendText("\n\n").appendValue(formatResponse(response));

                    return false;
                }

                pendingDocuments.remove(node.get("_index").asText() + "/" + node.get("_id").asText());

            }

            if (!pendingDocuments.isEmpty()) {
                mismatchDescription.appendText("result does not contain expected documents: ").appendValue(pendingDocuments);
                mismatchDescription.appendText("\n\n").appendValue(formatResponse(response));

                return false;
            }

            if (containsOpenSearchIndices && seenOpenSearchIndicesBuilder.build().size() == 0) {
                mismatchDescription.appendText("result does not contain expected opensearch indices");
                mismatchDescription.appendText("\n\n").appendValue(formatResponse(response));

                return false;
            }

            return true;
        }

        protected boolean matchesByIndices(
            Collection<?> collection,
            Description mismatchDescription,
            TestRestClient.HttpResponse response
        ) {
            ImmutableSet<String> expectedIndices = this.getExpectedIndices();
            ImmutableSet.Builder<String> seenIndicesBuilder = ImmutableSet.builderWithExpectedSize(expectedIndices.size());
            ImmutableSet.Builder<String> seenOpenSearchIndicesBuilder = new ImmutableSet.Builder<String>();

            for (Object object : collection) {
                String index = object.toString();

                if (containsOpenSearchIndices && (index.startsWith(".opendistro"))) {
                    seenOpenSearchIndicesBuilder.add(index);
                } else {
                    seenIndicesBuilder.add(index);
                }
            }

            ImmutableSet<String> seenIndices = seenIndicesBuilder.build();

            ImmutableSet<String> unexpectedIndices = Sets.difference(seenIndices, expectedIndices).immutableCopy();
            ImmutableSet<String> missingIndices = Sets.difference(expectedIndices, seenIndices).immutableCopy();

            if (containsOpenSearchIndices && seenOpenSearchIndicesBuilder.build().size() == 0) {
                missingIndices = ImmutableSet.<String>builderWithExpectedSize(missingIndices.size() + 1)
                    .addAll(missingIndices)
                    .add(".opensearch indices")
                    .build();
            }

            if (unexpectedIndices.isEmpty() && missingIndices.isEmpty()) {
                return true;
            } else {
                if (!missingIndices.isEmpty()) {
                    mismatchDescription.appendText("result does not contain expected indices; found: ")
                        .appendValue(seenIndices)
                        .appendText("; missing: ")
                        .appendValue(missingIndices)
                        .appendText("\n\n")
                        .appendText(formatResponse(response));
                }

                if (!unexpectedIndices.isEmpty()) {
                    mismatchDescription.appendText("result does contain indices that were not expected: ")
                        .appendValue(unexpectedIndices)
                        .appendText("\n\n")
                        .appendText(formatResponse(response));
                }
                return false;
            }
        }

        private Set<String> getExpectedDocuments() {
            Set<String> pendingDocuments = new HashSet<>();

            for (Map.Entry<String, TestIndexLike> entry : indexNameMap.entrySet()) {
                for (String id : entry.getValue().documentIds()) {
                    pendingDocuments.add(entry.getKey() + "/" + id);
                }
            }

            return pendingDocuments;
        }

        @Override
        public IndexMatcher but(IndexMatcher other) {
            if (other instanceof LimitedToMatcher) {
                return new ContainsExactlyMatcher(
                    testIndicesIntersection(this.indexNameMap, ((LimitedToMatcher) other).indexNameMap), //
                    this.containsOpenSearchIndices && other.containsOpenSearchIndices(), //
                    this.jsonPath,
                    this.statusCodeWhenEmpty
                );
            } else if (other instanceof ContainsExactlyMatcher) {
                return new ContainsExactlyMatcher(
                    testIndicesIntersection(this.indexNameMap, ((ContainsExactlyMatcher) other).indexNameMap), //
                    this.containsOpenSearchIndices && other.containsOpenSearchIndices(), //
                    this.jsonPath,
                    this.statusCodeWhenEmpty
                );
            } else if (other instanceof UnlimitedMatcher) {
                return new ContainsExactlyMatcher(
                    this.indexNameMap, //
                    this.containsOpenSearchIndices && other.containsOpenSearchIndices(), //
                    this.jsonPath,
                    this.statusCodeWhenEmpty
                );
            } else {
                throw new RuntimeException("Unexpected argument " + other);
            }
        }

        @Override
        public boolean isCoveredBy(IndexMatcher other) {
            // Returns true of other provides at least all indices as this
            // Examples:
            //
            // this: a, b, c
            // other: b, c
            // -> a missing -> false
            //
            // this: a, b
            // other: a, b, c
            // -> true

            if (other instanceof LimitedToMatcher) {
                return ((LimitedToMatcher) other).getExpectedIndices().containsAll(this.getExpectedIndices());
            } else if (other instanceof ContainsExactlyMatcher) {
                return ((ContainsExactlyMatcher) other).getExpectedIndices().containsAll(this.getExpectedIndices());
            } else if (other instanceof UnlimitedMatcher) {
                return true;
            } else {
                throw new RuntimeException("Unexpected argument " + other);
            }
        }

        @Override
        public IndexMatcher at(String jsonPath) {
            return new ContainsExactlyMatcher(indexNameMap, containsOpenSearchIndices, jsonPath, statusCodeWhenEmpty);
        }

        @Override
        public IndexMatcher whenEmpty(int statusCode) {
            return new ContainsExactlyMatcher(indexNameMap, containsOpenSearchIndices, jsonPath, statusCode);
        }

        @Override
        public boolean covers(TestIndex testIndex) {
            return indexNameMap.containsKey(testIndex.name());
        }

    }

    public static class LimitedToMatcher extends AbstractIndexMatcher implements IndexMatcher {

        public LimitedToMatcher(Map<String, TestIndexLike> indexNameMap) {
            super(indexNameMap, false);
        }

        public LimitedToMatcher(Map<String, TestIndexLike> indexNameMap, String jsonPath, int statusCodeWhenEmpty) {
            super(indexNameMap, false, jsonPath, statusCodeWhenEmpty);
        }

        @Override
        public void describeTo(Description description) {
            if (indexNameMap.isEmpty()) {
                if (this.statusCodeWhenEmpty == 200) {
                    description.appendText("a 200 OK response with an empty result set");
                } else {
                    description.appendText("a response with status code " + this.statusCodeWhenEmpty);
                }
            } else {
                description.appendText(
                    "a 200 OK response no indices other than " + indexNameMap.keySet().stream().collect(Collectors.joining(", "))
                );
            }
        }

        @Override
        protected boolean matchesImpl(Collection<?> collection, Description mismatchDescription, TestRestClient.HttpResponse response) {
            boolean checkDocs = false;

            for (Object object : collection) {
                if (object instanceof String) {
                    checkDocs = false;
                    break;
                } else if (object instanceof Map && ((Map<?, ?>) object).containsKey("_index")) {
                    checkDocs = true;
                    break;
                } else {
                    mismatchDescription.appendText("unexpected value ")
                        .appendValue(object)
                        .appendText(" (")
                        .appendValue(object != null ? object.getClass().toString() : "null")
                        .appendText(")\n\n")
                        .appendText(formatResponse(response));
                    return false;
                }
            }

            if (checkDocs) {
                return matchesByDocs(collection, mismatchDescription, response);
            } else {
                return matchesByIndices(collection, mismatchDescription, response);
            }
        }

        @Override
        public IndexMatcher but(IndexMatcher other) {
            if (other instanceof LimitedToMatcher) {

                return new LimitedToMatcher(
                    filterTestIndices(this.indexNameMap, ((LimitedToMatcher) other).getExpectedIndices()),
                    this.jsonPath,
                    this.statusCodeWhenEmpty
                );
            } else if (other instanceof ContainsExactlyMatcher) {
                return new ContainsExactlyMatcher(
                    filterTestIndices(this.indexNameMap, ((ContainsExactlyMatcher) other).getExpectedIndices()),
                    false,
                    this.jsonPath,
                    this.statusCodeWhenEmpty
                );
            } else if (other instanceof UnlimitedMatcher) {
                return this;
            } else {
                throw new RuntimeException("Unexpected argument " + other);
            }
        }

        @Override
        public boolean covers(TestIndex testIndex) {
            return indexNameMap.containsKey(testIndex.name());
        }

        @Override
        public boolean isCoveredBy(IndexMatcher other) {
            if (other instanceof LimitedToMatcher) {
                return ((LimitedToMatcher) other).getExpectedIndices().containsAll(this.getExpectedIndices());
            } else if (other instanceof ContainsExactlyMatcher) {
                return ((ContainsExactlyMatcher) other).getExpectedIndices().containsAll(this.getExpectedIndices());
            } else if (other instanceof UnlimitedMatcher) {
                return true;
            } else {
                throw new RuntimeException("Unexpected argument " + other);
            }
        }

        protected boolean matchesByDocs(Collection<?> collection, Description mismatchDescription, TestRestClient.HttpResponse response) {
            ImmutableSet<String> expectedIndices = this.getExpectedIndices();
            ImmutableSet.Builder<String> seenIndicesBuilder = ImmutableSet.builderWithExpectedSize(expectedIndices.size());

            for (Object object : collection) {
                seenIndicesBuilder.add(DefaultObjectMapper.objectMapper.valueToTree(object).get("_index").asText());
            }

            ImmutableSet<String> seenIndices = seenIndicesBuilder.build();
            ImmutableSet<String> unexpectedIndices = Sets.difference(seenIndices, expectedIndices).immutableCopy();

            if (unexpectedIndices.isEmpty()) {
                return true;
            } else {
                mismatchDescription.appendText("result does contain indices that were not expected: ")
                    .appendValue(unexpectedIndices)
                    .appendText("\n\n")
                    .appendValue(formatResponse(response));
                return false;
            }
        }

        protected boolean matchesByIndices(
            Collection<?> collection,
            Description mismatchDescription,
            TestRestClient.HttpResponse response
        ) {
            ImmutableSet<String> expectedIndices = this.getExpectedIndices();
            ImmutableSet.Builder<String> seenIndicesBuilder = ImmutableSet.builderWithExpectedSize(expectedIndices.size());

            for (Object object : collection) {
                seenIndicesBuilder.add(object.toString());
            }

            ImmutableSet<String> seenIndices = seenIndicesBuilder.build();
            ImmutableSet<String> unexpectedIndices = Sets.difference(seenIndices, expectedIndices).immutableCopy();

            if (unexpectedIndices.isEmpty()) {
                return true;
            } else {
                mismatchDescription.appendText("result does contain indices that were not expected: ")
                    .appendValue(unexpectedIndices)
                    .appendText("\n\n")
                    .appendValue(formatResponse(response));
                return false;
            }
        }

        @Override
        public IndexMatcher at(String jsonPath) {
            return new ContainsExactlyMatcher(indexNameMap, containsOpenSearchIndices, jsonPath, statusCodeWhenEmpty);
        }

        @Override
        public IndexMatcher whenEmpty(int statusCode) {
            return new ContainsExactlyMatcher(indexNameMap, containsOpenSearchIndices, jsonPath, statusCode);
        }

    }

    public static class UnlimitedMatcher extends DiagnosingMatcher<Object> implements IndexMatcher {

        private final boolean containsOpenSearchIndices;

        public UnlimitedMatcher() {
            this.containsOpenSearchIndices = false;
        }

        public UnlimitedMatcher(boolean containsOpenSearchIndices) {
            this.containsOpenSearchIndices = containsOpenSearchIndices;
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("unlimited indices");
        }

        @Override
        protected boolean matches(Object item, Description mismatchDescription) {
            if (item instanceof TestRestClient.HttpResponse) {
                TestRestClient.HttpResponse response = (TestRestClient.HttpResponse) item;

                if (response.getStatusCode() != 200) {
                    mismatchDescription.appendText("Expected status code 200 but status was: ")
                        .appendValue(response.getStatusCode() + " " + response.getStatusReason());
                    return false;
                }
            }

            return true;
        }

        @Override
        public IndexMatcher but(IndexMatcher other) {
            return other;
        }

        @Override
        public boolean isCoveredBy(IndexMatcher other) {
            if (other instanceof UnlimitedMatcher) {
                return true;
            } else {
                return false;
            }
        }

        @Override
        public IndexMatcher at(String jsonPath) {
            return this;
        }

        @Override
        public IndexMatcher whenEmpty(int statusCode) {
            return this;
        }

        @Override
        public IndexMatcher butFailIfIncomplete(IndexMatcher other, int statusCode) {
            return this;
        }

        @Override
        public boolean isEmpty() {
            return false;
        }

        @Override
        public boolean containsOpenSearchIndices() {
            return containsOpenSearchIndices;
        }

        @Override
        public int size() {
            throw new IllegalStateException("The UnlimitedMatcher cannot specify a size");
        }

        @Override
        public boolean containsDocument(String id) {
            return true;
        }

        @Override
        public boolean covers(TestIndex testIndex) {
            return true;
        }
    }

    public static class StatusCodeMatcher extends DiagnosingMatcher<Object> implements IndexMatcher {
        private int expectedStatusCode = 403;

        public StatusCodeMatcher(int expectedStatusCode) {
            this.expectedStatusCode = expectedStatusCode;
        }

        public StatusCodeMatcher withStatus(int expectedStatusCode) {
            this.expectedStatusCode = expectedStatusCode;
            return this;
        }

        @Override
        public IndexMatcher but(IndexMatcher other) {
            return this;
        }

        @Override
        public IndexMatcher at(String jsonPath) {
            return this;
        }

        @Override
        public IndexMatcher whenEmpty(int statusCode) {
            return this;
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("a response with status code " + this.expectedStatusCode);
        }

        @Override
        public IndexMatcher butFailIfIncomplete(IndexMatcher other, int statusCode) {
            return new StatusCodeMatcher(statusCode);
        }

        @Override
        protected boolean matches(Object item, Description mismatchDescription) {
            if (item instanceof TestRestClient.HttpResponse) {
                TestRestClient.HttpResponse response = (TestRestClient.HttpResponse) item;

                if (response.getStatusCode() != this.expectedStatusCode) {
                    mismatchDescription.appendText("Status was: ")
                        .appendValue(response.getStatusCode() + " " + response.getStatusReason())
                        .appendText("\n\n")
                        .appendText(formatResponse(response));
                    return false;
                } else {
                    return true;
                }
            } else {
                mismatchDescription.appendText("Did not get HttpResponse ").appendValue(item);

                return false;
            }
        }

        @Override
        public boolean isEmpty() {
            return true;
        }

        @Override
        public boolean containsOpenSearchIndices() {
            return true;
        }

        @Override
        public boolean isCoveredBy(IndexMatcher other) {
            return false;
        }

        @Override
        public int size() {
            return 0;
        }

        @Override
        public boolean containsDocument(String id) {
            return false;
        }

        @Override
        public boolean covers(TestIndex testIndex) {
            return false;
        }
    }

    public static interface IndexMatcher extends Matcher<Object> {
        IndexMatcher but(IndexMatcher other);

        IndexMatcher butFailIfIncomplete(IndexMatcher other, int statusCode);

        IndexMatcher at(String jsonPath);

        IndexMatcher whenEmpty(int statusCode);

        boolean isEmpty();

        int size();

        boolean isCoveredBy(IndexMatcher other);

        default IndexMatcher butForbiddenIfIncomplete(IndexMatcher other) {
            return butFailIfIncomplete(other, 403);
        }

        boolean containsOpenSearchIndices();

        boolean containsDocument(String id);

        boolean covers(TestIndex testIndex);
    }

    static abstract class AbstractIndexMatcher extends DiagnosingMatcher<Object> implements IndexMatcher {
        protected final Map<String, TestIndexLike> indexNameMap;
        protected final String jsonPath;
        protected final int statusCodeWhenEmpty;
        protected final boolean containsOpenSearchIndices;

        AbstractIndexMatcher(Map<String, TestIndexLike> indexNameMap, boolean containsOpenSearchIndices) {
            this.indexNameMap = indexNameMap;
            this.jsonPath = null;
            this.statusCodeWhenEmpty = 200;
            this.containsOpenSearchIndices = containsOpenSearchIndices;
        }

        AbstractIndexMatcher(
            Map<String, TestIndexLike> indexNameMap,
            boolean containsOpenSearchIndices,
            String jsonPath,
            int statusCodeWhenEmpty
        ) {
            this.indexNameMap = indexNameMap;
            this.jsonPath = jsonPath;
            this.statusCodeWhenEmpty = statusCodeWhenEmpty;
            this.containsOpenSearchIndices = containsOpenSearchIndices;
        }

        @Override
        protected boolean matches(Object item, Description mismatchDescription) {
            TestRestClient.HttpResponse response = null;

            if (item instanceof TestRestClient.HttpResponse) {
                response = (TestRestClient.HttpResponse) item;

                if (indexNameMap.isEmpty()) {
                    if (response.getStatusCode() != this.statusCodeWhenEmpty) {
                        mismatchDescription.appendText("Status was: ")
                            .appendValue(response.getStatusCode() + " " + response.getStatusReason())
                            .appendText("\n\n")
                            .appendText(formatResponse(response));
                        return false;
                    }

                    if (response.getStatusCode() != 200) {
                        return true;
                    }
                }

                try {
                    if (response.getBody().startsWith(START_ARRAY.asString())) {
                        item = DefaultObjectMapper.objectMapper.readValue(response.getBody(), List.class);
                    } else {
                        item = DefaultObjectMapper.objectMapper.readValue(response.getBody(), Map.class);
                    }
                } catch (JsonProcessingException e) {
                    mismatchDescription.appendText("Unable to parse body: ").appendValue(e.getMessage());
                    return false;
                }
            }

            if (jsonPath != null) {
                Configuration config = Configuration.builder().jsonProvider(new JacksonJsonProvider()).build();

                item = JsonPath.using(config).parse(item).read(jsonPath);

                if (item == null) {
                    mismatchDescription.appendText("Unable to find JSON Path: ")
                        .appendValue(jsonPath)
                        .appendText("\n\n")
                        .appendText(formatResponse(response));
                    return false;
                }
            }

            if (!(item instanceof Collection)) {
                item = Collections.singleton(item);
            }

            return matchesImpl((Collection<?>) item, mismatchDescription, response);
        }

        protected abstract boolean matchesImpl(
            Collection<?> collection,
            Description mismatchDescription,
            TestRestClient.HttpResponse response
        );

        @Override
        public IndexMatcher butFailIfIncomplete(IndexMatcher other, int statusCode) {
            if (other instanceof UnlimitedMatcher) {
                return this;
            }

            HashMap<String, TestIndexLike> unmatched = new HashMap<>(this.indexNameMap);
            unmatched.keySet().removeAll(((AbstractIndexMatcher) other).indexNameMap.keySet());

            if (!unmatched.isEmpty()) {
                return new StatusCodeMatcher(statusCode);
            } else {
                return this.but(other);
            }
        }

        @Override
        public boolean isEmpty() {
            return indexNameMap.isEmpty();
        }

        @Override
        public int size() {
            if (!containsOpenSearchIndices) {
                return indexNameMap.size();
            } else {
                throw new RuntimeException("Size cannot be exactly specified because containsOpenSearchIndices is true");
            }
        }

        @Override
        public boolean containsOpenSearchIndices() {
            return containsOpenSearchIndices;
        }

        @Override
        public boolean containsDocument(String id) {
            for (TestIndexLike indexLike : this.indexNameMap.values()) {
                if (indexLike.documentIds().contains(id)) {
                    return true;
                }
            }

            return false;
        }

        protected Map<String, TestIndexLike> testIndicesIntersection(Map<String, TestIndexLike> map1, Map<String, TestIndexLike> map2) {
            Map<String, TestIndexLike> result = new HashMap<>();

            for (Map.Entry<String, TestIndexLike> entry : map1.entrySet()) {
                String key = entry.getKey();
                TestIndexLike index1 = entry.getValue();
                TestIndexLike index2 = map2.get(key);

                if (index2 == null) {
                    continue;
                }

                result.put(key, index1.intersection(index2));
            }

            return Collections.unmodifiableMap(result);
        }

        protected Map<String, TestIndexLike> filterTestIndices(Map<String, TestIndexLike> indexMap, Set<String> keysToKeep) {
            return indexMap.entrySet()
                .stream()
                .filter(entry -> keysToKeep.contains(entry.getKey()))
                .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, Map.Entry::getValue));
        }

        protected ImmutableSet<String> getExpectedIndices() {
            return ImmutableSet.copyOf(indexNameMap.keySet());
        }

    }

    private static String formatResponse(TestRestClient.HttpResponse response) {
        if (response == null) {
            return "";
        }

        String start = response.getStatusCode() + " " + response.getStatusReason() + "\n";

        if (response.isJsonContentType()) {
            return start + response.bodyAsJsonNode().toPrettyString();
        } else {
            return start + response.getBody();
        }
    }
}
