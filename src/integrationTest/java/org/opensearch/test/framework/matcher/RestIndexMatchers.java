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
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestIndex;
import org.opensearch.test.framework.data.TestIndexOrAliasOrDatastream;

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
public class RestIndexMatchers {

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
            boolean containsOpenSearchSecurityIndex = false;

            for (TestIndexOrAliasOrDatastream testIndex : testIndices) {
                if (testIndex == TestIndex.openSearchSecurityConfigIndex()) {
                    containsOpenSearchSecurityIndex = true;
                } else {
                    indexNameMap.put(testIndex.name(), testIndex);
                }
            }

            return new ContainsExactlyMatcher(indexNameMap, containsOpenSearchSecurityIndex);
        }
    }

    /**
     * Matchers that are associated with TestSecurityConfig.User objects via the indexMatcher() method
     */
    public interface OnUserIndexMatcher extends IndexMatcher {

        static OnUserIndexMatcher limitedTo(TestIndexOrAliasOrDatastream... testIndices) {
            return limitedTo(Arrays.asList(testIndices));
        }

        static OnUserIndexMatcher limitedTo(Collection<TestIndexOrAliasOrDatastream> testIndices) {
            Map<String, TestIndexOrAliasOrDatastream> indexNameMap = new HashMap<>();

            for (TestIndexOrAliasOrDatastream testIndex : testIndices) {
                indexNameMap.put(testIndex.name(), testIndex);
            }

            return new LimitedToMatcher(indexNameMap);
        }

        static IndexMatcher unlimited() {
            return new UnlimitedMatcher();
        }

        static IndexMatcher unlimitedIncludingOpenSearchSecurityIndex() {
            return new UnlimitedMatcher(true);
        }

        static IndexMatcher limitedToNone() {
            return new LimitedToMatcher(Collections.emptyMap());
        }

        /**
         * Adds the given indices to the set of indices this matcher is limited to.
         * @param testIndices additional indices for the limitation.
         * @return a new IndexMatcher instance with the new limit.
         */
        OnUserIndexMatcher and(TestIndexOrAliasOrDatastream... testIndices);
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

        /**
         * Returns true if the set of indices is expected to contain the security config index
         */
        boolean containsOpenSearchSecurityIndex();

        /**
         * Returns true if this matcher expects the given index to be present
         */
        boolean covers(TestIndexOrAliasOrDatastream testIndex);

        /**
         * Returns true if this matcher expects all the given indices to be present
         */
        default boolean coversAll(TestIndexOrAliasOrDatastream... testIndices) {
            return Stream.of(testIndices).allMatch(this::covers);
        }

        default boolean coversAll(Collection<TestIndexOrAliasOrDatastream> testIndices) {
            return testIndices.stream().allMatch(this::covers);
        }
    }

    // ----------------------------------------------------------------------------------
    // Actual matcher implementations
    // (created by static methods in OnResponseIndexMatcher and OnUserIndexMatcher above)
    // ----------------------------------------------------------------------------------

    /**
     * Base implementation for all matchers. The primary working mode of these matchers is to
     * expect TestRestClient.HttpResponse objects and to extract index names from the response
     * body via a jsonPath (specified with the at() method). However, the matchers will also
     * work on any string collection; then, the json path is not necessary.
     */
    static abstract class AbstractIndexMatcher extends DiagnosingMatcher<Object> implements IndexMatcher {
        /**
         * The indices expected by this matcher.
         */
        protected final Map<String, TestIndexOrAliasOrDatastream> expectedIndices;

        /**
         * The matcher will extract the indices from the REST response body using this JSON path expression.
         */
        protected final String jsonPath;

        /**
         * If the matcher expects an empty set of indices, this can actually mean two things:
         * <ol>
         *     <li>The response is expected to be successful (i.e. has a 200 OK status) and returns an empty set of indices</li>
         *     <li>The response has failed with a non 200 status code</li>
         * </ol>
         * The expected status code is specified by this matcher. This matcher will be used to assert the status code when
         * the expected set of indices is empty.
         */
        protected final RestMatchers.HttpResponseMatcher statusCodeWhenEmpty;

        /**
         * This is true if we also expect the .opendistro_security index. In case we gain further
         * system indices that are present by default on an int test cluster, this can be expanded to cover also these.
         */
        protected final boolean containsOpenSearchSecurityIndex;

        AbstractIndexMatcher(Map<String, TestIndexOrAliasOrDatastream> expectedIndices, boolean containsOpenSearchSecurityIndex) {
            this.expectedIndices = expectedIndices;
            this.jsonPath = null;
            this.statusCodeWhenEmpty = RestMatchers.isOk();
            this.containsOpenSearchSecurityIndex = containsOpenSearchSecurityIndex;
        }

        AbstractIndexMatcher(
            Map<String, TestIndexOrAliasOrDatastream> expectedIndices,
            boolean containsOpenSearchSecurityIndex,
            String jsonPath,
            RestMatchers.HttpResponseMatcher statusCodeWhenEmpty
        ) {
            this.expectedIndices = expectedIndices;
            this.jsonPath = jsonPath;
            this.statusCodeWhenEmpty = statusCodeWhenEmpty;
            this.containsOpenSearchSecurityIndex = containsOpenSearchSecurityIndex;
        }

        @Override
        protected boolean matches(Object item, Description mismatchDescription) {
            TestRestClient.HttpResponse response = null;

            if (item instanceof TestRestClient.HttpResponse) {
                response = (TestRestClient.HttpResponse) item;

                if (expectedIndices.isEmpty()) {
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

        /**
         * This is called by the main matches() method after the indices have been extracted
         * from the HTTP response body. The found indices will be passed as the actualItems parameter.
         *
         * @param actualItems The found indices. This is expected to be strings.
         * @param mismatchDescription In case the matcher finds a mismatch, the description should be appended to this object.
         * @param response The REST response we are asserting against. Optional.
         * @return true if the assertion was successful, false it it failed.
         */
        protected abstract boolean matchesImpl(
            Collection<?> actualItems,
            Description mismatchDescription,
            TestRestClient.HttpResponse response
        );

        @Override
        public boolean isEmpty() {
            return expectedIndices.isEmpty();
        }

        @Override
        public int size() {
            if (!containsOpenSearchSecurityIndex) {
                return expectedIndices.size();
            } else {
                return expectedIndices.size() + 1;
            }
        }

        @Override
        public boolean containsOpenSearchSecurityIndex() {
            return containsOpenSearchSecurityIndex;
        }

        /**
         * Calculates the intersection of the two given Map objects.
         */
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

                result.put(key, index1);
            }

            return Collections.unmodifiableMap(result);
        }

        protected ImmutableSet<String> getExpectedIndices() {
            return ImmutableSet.copyOf(expectedIndices.keySet());
        }

        /**
         * Returns a formatted version of the response. This can be used in the mismatch description.
         */
        protected static String formatResponse(TestRestClient.HttpResponse response) {
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

    /**
     * This asserts that the item we assert on contains a set of indices that exactly corresponds to the expected
     * indices (i.e., not fewer and not more indices). This is usually used to match against REST responses.
     */
    static class ContainsExactlyMatcher extends AbstractIndexMatcher implements OnResponseIndexMatcher {
        private static final Pattern DS_BACKING_INDEX_PATTERN = Pattern.compile("\\.ds-(.+)-[0-9]+");

        ContainsExactlyMatcher(Map<String, TestIndexOrAliasOrDatastream> indexNameMap, boolean containsOpenSearchSecurityIndex) {
            super(indexNameMap, containsOpenSearchSecurityIndex);
        }

        ContainsExactlyMatcher(
            Map<String, TestIndexOrAliasOrDatastream> indexNameMap,
            boolean containsOpenSearchSecurityIndex,
            String jsonPath,
            RestMatchers.HttpResponseMatcher statusCodeWhenEmpty
        ) {
            super(indexNameMap, containsOpenSearchSecurityIndex, jsonPath, statusCodeWhenEmpty);
        }

        @Override
        public void describeTo(Description description) {
            if (expectedIndices.isEmpty()) {
                if (this.statusCodeWhenEmpty.statusCode() == 200) {
                    description.appendText("a 200 OK response with an empty result set");
                } else {
                    this.statusCodeWhenEmpty.describeTo(description);
                    description.appendText("a response with status code " + this.statusCodeWhenEmpty);
                }
            } else {
                description.appendText(
                    "a 200 OK response with exactly the indices " + expectedIndices.keySet().stream().collect(Collectors.joining(", "))
                );
            }
        }

        @Override
        protected boolean matchesImpl(Collection<?> actualItems, Description mismatchDescription, TestRestClient.HttpResponse response) {
            // Flatten the collection
            actualItems = actualItems.stream()
                .flatMap(e -> e instanceof Collection ? ((Collection<?>) e).stream() : Stream.of(e))
                .collect(Collectors.toSet());

            return matchesByIndices(actualItems, mismatchDescription, response);
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

                if (containsOpenSearchSecurityIndex && (index.equals(ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX))) {
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

            if (containsOpenSearchSecurityIndex && seenOpenSearchIndicesBuilder.build().size() == 0) {
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
                    testIndicesIntersection(this.expectedIndices, ((LimitedToMatcher) other).expectedIndices), //
                    this.containsOpenSearchSecurityIndex && other.containsOpenSearchSecurityIndex(), //
                    this.jsonPath,
                    this.statusCodeWhenEmpty
                );
            } else if (other instanceof ContainsExactlyMatcher) {
                return new ContainsExactlyMatcher(
                    testIndicesIntersection(this.expectedIndices, ((ContainsExactlyMatcher) other).expectedIndices), //
                    this.containsOpenSearchSecurityIndex && other.containsOpenSearchSecurityIndex(), //
                    this.jsonPath,
                    this.statusCodeWhenEmpty
                );
            } else if (other instanceof UnlimitedMatcher) {
                return new ContainsExactlyMatcher(
                    this.expectedIndices, //
                    this.containsOpenSearchSecurityIndex && other.containsOpenSearchSecurityIndex(), //
                    this.jsonPath,
                    this.statusCodeWhenEmpty
                );
            } else {
                throw new RuntimeException("Unexpected argument " + other);
            }
        }

        @Override
        public OnResponseIndexMatcher at(String jsonPath) {
            return new ContainsExactlyMatcher(expectedIndices, containsOpenSearchSecurityIndex, jsonPath, statusCodeWhenEmpty);
        }

        @Override
        public OnResponseIndexMatcher whenEmpty(RestMatchers.HttpResponseMatcher statusCode) {
            return new ContainsExactlyMatcher(expectedIndices, containsOpenSearchSecurityIndex, jsonPath, statusCode);
        }

        @Override
        public boolean covers(TestIndexOrAliasOrDatastream testIndex) {
            return expectedIndices.containsKey(testIndex.name());
        }

        @Override
        public OnResponseIndexMatcher butFailIfIncomplete(IndexMatcher other, RestMatchers.HttpResponseMatcher statusCode) {
            if (other instanceof UnlimitedMatcher) {
                return this;
            }

            HashMap<String, TestIndexOrAliasOrDatastream> unmatched = new HashMap<>(this.expectedIndices);
            unmatched.keySet().removeAll(((AbstractIndexMatcher) other).expectedIndices.keySet());

            if (!unmatched.isEmpty()) {
                return new StatusCodeMatcher(statusCode);
            } else {
                return this.reducedBy(other);
            }
        }
    }

    /**
     * Just asserts on the status code of a response. This is usually only used for failure status codes which
     * are expected when the expected set of indices is empty. In this case, we do not apply any JSON path
     * extractions, as we expect the response body to be just an error message.
     */
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
        public boolean containsOpenSearchSecurityIndex() {
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

    /**
     * This asserts that the item we assert on contains not more than the expected indices.
     * Usually, this is only associated with TestUser objects and used to reduce ContainsExactly matchers
     * to even more limited ContainsExactly matchers.
     */
    static class LimitedToMatcher extends AbstractIndexMatcher implements OnUserIndexMatcher {

        LimitedToMatcher(Map<String, TestIndexOrAliasOrDatastream> indexNameMap) {
            super(indexNameMap, false);
        }

        @Override
        public void describeTo(Description description) {
            if (expectedIndices.isEmpty()) {
                if (this.statusCodeWhenEmpty.statusCode() == 200) {
                    description.appendText("a 200 OK response with an empty result set");
                } else {
                    this.statusCodeWhenEmpty.describeTo(description);
                }
            } else {
                description.appendText(
                    "a 200 OK response no indices other than " + expectedIndices.keySet().stream().collect(Collectors.joining(", "))
                );
            }
        }

        @Override
        protected boolean matchesImpl(Collection<?> actualItems, Description mismatchDescription, TestRestClient.HttpResponse response) {
            return matchesByIndices(actualItems, mismatchDescription, response);
        }

        @Override
        public boolean covers(TestIndexOrAliasOrDatastream testIndex) {
            return expectedIndices.containsKey(testIndex.name());
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
        public OnUserIndexMatcher and(TestIndexOrAliasOrDatastream... testIndices) {
            Map<String, TestIndexOrAliasOrDatastream> indexNameMap = new HashMap<>(this.expectedIndices);

            for (TestIndexOrAliasOrDatastream testIndex : testIndices) {
                indexNameMap.put(testIndex.name(), testIndex);
            }

            return new LimitedToMatcher(indexNameMap);
        }
    }

    /**
     * This does no assertion on the expected indices. Usually, this is only associated with TestUser objects and used
     * to signal that ContainsExactly matchers do not need to be reduced.
     */
    static class UnlimitedMatcher extends DiagnosingMatcher<Object> implements OnUserIndexMatcher {

        private final boolean containsOpenSearchSecurityIndex;

        UnlimitedMatcher() {
            this.containsOpenSearchSecurityIndex = false;
        }

        UnlimitedMatcher(boolean containsOpenSearchSecurityIndex) {
            this.containsOpenSearchSecurityIndex = containsOpenSearchSecurityIndex;
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("unlimited indices");
        }

        @Override
        protected boolean matches(Object item, Description mismatchDescription) {
            if (item instanceof TestRestClient.HttpResponse response) {
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
        public boolean containsOpenSearchSecurityIndex() {
            return containsOpenSearchSecurityIndex;
        }

        @Override
        public int size() {
            throw new IllegalStateException("The UnlimitedMatcher cannot specify a size");
        }

        @Override
        public boolean covers(TestIndexOrAliasOrDatastream testIndex) {
            return true;
        }

        @Override
        public OnUserIndexMatcher and(TestIndexOrAliasOrDatastream... testIndices) {
            return this;
        }
    }
}
