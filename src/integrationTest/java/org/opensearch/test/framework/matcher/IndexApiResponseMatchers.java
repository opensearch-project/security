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

package org.opensearch.test.framework.matcher;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.hamcrest.Description;
import org.hamcrest.DiagnosingMatcher;
import org.hamcrest.Matcher;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestIndexOrAliasOrDatastream;
import org.opensearch.test.framework.cluster.TestRestClient;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.spi.json.JacksonJsonProvider;
import com.jayway.jsonpath.spi.mapper.JacksonMappingProvider;

import static com.fasterxml.jackson.core.JsonToken.START_ARRAY;

/**
 * This class provides Hamcrest matchers that can be used as test oracles on the HTTP responses of index REST APIs.
 * <p>
 * On a high level, the idea behind this class is like this:
 * <ul>
 *     <li>Test users can be associated with IndexMatcher instances via the TestSecurityConfig.User.indexMatcher() method. These define the maximum index space the user can operate on. There may be several index matchers per user, targeting different groups of operations.</li>
 *     <li>The results of REST API calls can be also associated with a maximum space of indices the operation could work on. Combined with the user specific index matcher, one can determine the intersection of the allowed indices and thus the indices that are allowed in the particular case. The matchers support JSON path expressions to extract information on indices from the HTTP response bodies. See IndexAuthorizationReadOnlyIntTests for examples.</li>
 * </ul>
 */
public class IndexApiResponseMatchers {

    /**
     * Matchers that are directly used on HTTP responses
     */
    public interface OnResponseIndexMatcher extends IndexMatcher {

        /**
         * Retrieves the actual indices from the HTTP response JSON body using this JSON path expression.
         * If you are asserting on an HTTP response, specifying a JSON path is madatory.
         */
        OnResponseIndexMatcher at(String jsonPath);

        /**
         * Calculates the intersection of this index matcher and the given other index matcher.
         * If this index matcher expects the indices a,b,c and the other index matcher expects b,c,d,
         * the resulting matcher will expect b,c.
         */
        OnResponseIndexMatcher reducedBy(IndexMatcher other);

        /**
         * Asserts on a specific HTTP status code if the set of indices expected by this matcher is empty.
         */
        OnResponseIndexMatcher whenEmpty(RestMatchers.HttpResponseMatcher statusCode);

        /**
         * Checks whether the indices of this matcher are a subset of the other index matcher.
         * If that is not the case, the given HTTP error will be expected in the response on which we are asserting.
         */
        OnResponseIndexMatcher butFailIfIncomplete(IndexMatcher other, RestMatchers.HttpResponseMatcher statusCode);

        default IndexMatcher butForbiddenIfIncomplete(IndexMatcher other) {
            return butFailIfIncomplete(other, RestMatchers.isForbidden());
        }

        /**
         * Asserts that a TestRestClient.HttpResponse object refers exactly to a specific set of indices.
         * <p>
         * Use this matcher like this:
         * <pre>
         *     assertThat(httpResponse, containsExactly(index_a1, index_a2).at("hits.hits[*]._index"))
         * </pre>
         * This will verify that the HTTP response lists the indices index_a1 and index_a2 at the place specified by the JSON path query.
         * <p>
         * It is possible to reduce the expected indices based on a test user this way:
         * <pre>
         *     assertThat(httpResponse, containsExactly(index_a1, index_a2).at("hits.hits[*]._index").reducedBy(user.inderMatcher("search"))
         * </pre>
         * This will calculate the intersection of the indices specified here and of the indices specified with the user index matcher.
         * The existence of exactly these indices will be asserted.
         * <p>
         * This method has the special feature that you can also specify data streams; it will then assert that
         * the backing indices of the data streams will be present in the result set.
         */
        public static OnResponseIndexMatcher containsExactly(TestIndexOrAliasOrDatastream... testIndices) {
            return containsExactly(Arrays.asList(testIndices));
        }

        public static OnResponseIndexMatcher containsExactly(Collection<TestIndexOrAliasOrDatastream> testIndices) {
            Map<String, TestIndexOrAliasOrDatastream> indexNameMap = new HashMap<>();
            boolean containsOpenSearchIndices = false;

            for (TestIndexOrAliasOrDatastream testIndex : testIndices) {
                if (testIndex == TestIndex.openSearchSecurityConfigIndex()) {
                    containsOpenSearchIndices = true;
                } else {
                    indexNameMap.put(testIndex.name(), testIndex);
                }
            }

            return new ContainsExactlyMatcher(indexNameMap, containsOpenSearchIndices);
        }
    }

    /**
     * Matchers that are associated with TestSecurityConfig.User objects via the indexMatcher() method
     */
    public interface OnUserIndexMatcher extends IndexMatcher {

        public static IndexMatcher limitedTo(TestIndexOrAliasOrDatastream... testIndices) {
            return limitedTo(Arrays.asList(testIndices));
        }

        public static IndexMatcher limitedTo(Collection<TestIndexOrAliasOrDatastream> testIndices) {
            Map<String, TestIndexOrAliasOrDatastream> indexNameMap = new HashMap<>();

            for (TestIndexOrAliasOrDatastream testIndex : testIndices) {
                indexNameMap.put(testIndex.name(), testIndex);
            }

            return new LimitedToMatcher(indexNameMap);
        }

        public static IndexMatcher unlimited() {
            return new UnlimitedMatcher();
        }

        public static IndexMatcher unlimitedIncludingOpenSearchSecurityIndex() {
            return new UnlimitedMatcher(true);
        }

        public static IndexMatcher limitedToNone() {
            return new LimitedToMatcher(Collections.emptyMap());
        }
    }

    /**
     * The returned IndexMatcher objects implement this interface.
     */
    public interface IndexMatcher extends Matcher<Object> {
        /**
         * Checks whether this matcher expects an empty set of indices.
         */
        boolean isEmpty();

        /**
         * Returns the number of indices expected by this matcher.
         */
        int size();

        boolean containsOpenSearchIndices();

        boolean covers(TestIndexOrAliasOrDatastream testIndex);

        default boolean coversAll(TestIndexOrAliasOrDatastream... testIndices) {
            return Stream.of(testIndices).allMatch(this::covers);
        }
    }

    static class ContainsExactlyMatcher extends AbstractIndexMatcher implements OnResponseIndexMatcher {
        private static final Pattern DS_BACKING_INDEX_PATTERN = Pattern.compile("\\.ds-(.+)-[0-9]+");

        ContainsExactlyMatcher(Map<String, TestIndexOrAliasOrDatastream> indexNameMap, boolean containsOpenSearchIndices) {
            super(indexNameMap, containsOpenSearchIndices);
        }

        ContainsExactlyMatcher(
            Map<String, TestIndexOrAliasOrDatastream> indexNameMap,
            boolean containsOpenSearchIndices,
            String jsonPath,
            RestMatchers.HttpResponseMatcher statusCodeWhenEmpty
        ) {
            super(indexNameMap, containsOpenSearchIndices, jsonPath, statusCodeWhenEmpty);
        }

        @Override
        public void describeTo(Description description) {
            if (indexNameMap.isEmpty()) {
                if (this.statusCodeWhenEmpty.statusCode() == 200) {
                    description.appendText("a 200 OK response with an empty result set");
                } else {
                    this.statusCodeWhenEmpty.describeTo(description);
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
            // Flatten the collection
            collection = collection.stream()
                .flatMap(e -> e instanceof Collection ? ((Collection<?>) e).stream() : Stream.of(e))
                .collect(Collectors.toSet());

            return matchesByIndices(collection, mismatchDescription, response);
        }

        protected boolean matchesByIndices(
            Collection<?> collection,
            Description mismatchDescription,
            TestRestClient.HttpResponse response
        ) {
            ImmutableSet<String> expectedIndices = this.getExpectedIndices();
            ImmutableSet.Builder<String> seenIndicesBuilder = ImmutableSet.builderWithExpectedSize(expectedIndices.size());
            ImmutableSet.Builder<String> seenOpenSearchIndicesBuilder = new ImmutableSet.Builder<>();

            for (Object object : collection) {
                String index = object.toString();

                if (containsOpenSearchIndices && (index.startsWith(".opendistro"))) {
                    seenOpenSearchIndicesBuilder.add(index);
                } else if (index.startsWith(".ds-")) {
                    // We do a special treatment for data stream backing indices. We convert these to the normal data streams if expected
                    // indices contains these.
                    java.util.regex.Matcher matcher = DS_BACKING_INDEX_PATTERN.matcher(index);

                    if (matcher.matches() && expectedIndices.contains(matcher.group(1))) {
                        seenIndicesBuilder.add(matcher.group(1));
                    } else {
                        seenIndicesBuilder.add(index);
                    }
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

        @Override
        public OnResponseIndexMatcher reducedBy(IndexMatcher other) {
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
        public OnResponseIndexMatcher at(String jsonPath) {
            return new ContainsExactlyMatcher(indexNameMap, containsOpenSearchIndices, jsonPath, statusCodeWhenEmpty);
        }

        @Override
        public OnResponseIndexMatcher whenEmpty(RestMatchers.HttpResponseMatcher statusCode) {
            return new ContainsExactlyMatcher(indexNameMap, containsOpenSearchIndices, jsonPath, statusCode);
        }

        @Override
        public boolean covers(TestIndexOrAliasOrDatastream testIndex) {
            return indexNameMap.containsKey(testIndex.name());
        }

        @Override
        public OnResponseIndexMatcher butFailIfIncomplete(IndexMatcher other, RestMatchers.HttpResponseMatcher statusCode) {
            if (other instanceof UnlimitedMatcher) {
                return this;
            }

            HashMap<String, TestIndexOrAliasOrDatastream> unmatched = new HashMap<>(this.indexNameMap);
            unmatched.keySet().removeAll(((AbstractIndexMatcher) other).indexNameMap.keySet());

            if (!unmatched.isEmpty()) {
                return new StatusCodeMatcher(statusCode);
            } else {
                return this.reducedBy(other);
            }
        }
    }

    static class StatusCodeMatcher extends DiagnosingMatcher<Object> implements OnResponseIndexMatcher {
        private RestMatchers.HttpResponseMatcher expectedStatusCode;

        public StatusCodeMatcher(RestMatchers.HttpResponseMatcher expectedStatusCode) {
            this.expectedStatusCode = expectedStatusCode;
        }

        @Override
        public void describeTo(Description description) {
            this.expectedStatusCode.describeTo(description);
        }

        @Override
        protected boolean matches(Object item, Description mismatchDescription) {
            return this.expectedStatusCode.matches(item, mismatchDescription);
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
        public int size() {
            return 0;
        }

        @Override
        public boolean covers(TestIndexOrAliasOrDatastream testIndex) {
            return false;
        }

        @Override
        public OnResponseIndexMatcher at(String jsonPath) {
            return this;
        }

        @Override
        public OnResponseIndexMatcher reducedBy(IndexMatcher other) {
            return this;
        }

        @Override
        public OnResponseIndexMatcher whenEmpty(RestMatchers.HttpResponseMatcher statusCode) {
            return this;
        }

        @Override
        public OnResponseIndexMatcher butFailIfIncomplete(IndexMatcher other, RestMatchers.HttpResponseMatcher statusCode) {
            return this;
        }
    }

    static class LimitedToMatcher extends AbstractIndexMatcher implements OnUserIndexMatcher {

        LimitedToMatcher(Map<String, TestIndexOrAliasOrDatastream> indexNameMap) {
            super(indexNameMap, false);
        }

        @Override
        public void describeTo(Description description) {
            if (indexNameMap.isEmpty()) {
                if (this.statusCodeWhenEmpty.statusCode() == 200) {
                    description.appendText("a 200 OK response with an empty result set");
                } else {
                    this.statusCodeWhenEmpty.describeTo(description);
                }
            } else {
                description.appendText(
                    "a 200 OK response no indices other than " + indexNameMap.keySet().stream().collect(Collectors.joining(", "))
                );
            }
        }

        @Override
        protected boolean matchesImpl(Collection<?> collection, Description mismatchDescription, TestRestClient.HttpResponse response) {
            return matchesByIndices(collection, mismatchDescription, response);
        }

        @Override
        public boolean covers(TestIndexOrAliasOrDatastream testIndex) {
            return indexNameMap.containsKey(testIndex.name());
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
    }

    static class UnlimitedMatcher extends DiagnosingMatcher<Object> implements OnUserIndexMatcher {

        private final boolean containsOpenSearchIndices;

        UnlimitedMatcher() {
            this.containsOpenSearchIndices = false;
        }

        UnlimitedMatcher(boolean containsOpenSearchIndices) {
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
        public boolean covers(TestIndexOrAliasOrDatastream testIndex) {
            return true;
        }
    }

    static abstract class AbstractIndexMatcher extends DiagnosingMatcher<Object> implements IndexMatcher {
        protected final Map<String, TestIndexOrAliasOrDatastream> indexNameMap;
        protected final String jsonPath;
        protected final RestMatchers.HttpResponseMatcher statusCodeWhenEmpty;
        protected final boolean containsOpenSearchIndices;

        AbstractIndexMatcher(Map<String, TestIndexOrAliasOrDatastream> indexNameMap, boolean containsOpenSearchIndices) {
            this.indexNameMap = indexNameMap;
            this.jsonPath = null;
            this.statusCodeWhenEmpty = RestMatchers.isOk();
            this.containsOpenSearchIndices = containsOpenSearchIndices;
        }

        AbstractIndexMatcher(
            Map<String, TestIndexOrAliasOrDatastream> indexNameMap,
            boolean containsOpenSearchIndices,
            String jsonPath,
            RestMatchers.HttpResponseMatcher statusCodeWhenEmpty
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
                    if (response.getStatusCode() != this.statusCodeWhenEmpty.statusCode()) {
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
                Configuration config = Configuration.builder()
                    .jsonProvider(new JacksonJsonProvider())
                    .mappingProvider(new JacksonMappingProvider())
                    .evaluationListener()
                    .options(Option.SUPPRESS_EXCEPTIONS)
                    .build();

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

        protected Map<String, TestIndexOrAliasOrDatastream> testIndicesIntersection(
            Map<String, TestIndexOrAliasOrDatastream> map1,
            Map<String, TestIndexOrAliasOrDatastream> map2
        ) {
            Map<String, TestIndexOrAliasOrDatastream> result = new HashMap<>();

            for (Map.Entry<String, TestIndexOrAliasOrDatastream> entry : map1.entrySet()) {
                String key = entry.getKey();
                TestIndexOrAliasOrDatastream index1 = entry.getValue();
                TestIndexOrAliasOrDatastream index2 = map2.get(key);

                if (index2 == null) {
                    continue;
                }

                result.put(key, index1.intersection(index2));
            }

            return Collections.unmodifiableMap(result);
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
