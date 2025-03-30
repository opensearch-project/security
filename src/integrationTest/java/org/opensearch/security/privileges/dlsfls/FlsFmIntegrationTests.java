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
package org.opensearch.security.privileges.dlsfls;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.collect.ImmutableMap;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.bouncycastle.util.encoders.Hex;

import org.opensearch.plugin.mapper.MapperSizePlugin;
import org.opensearch.test.framework.TestData;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import com.rfksystems.blake2b.Blake2b;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.correspondingToDocument;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.emptyHits;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.hasAggregation;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.hasSearchHits;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.hasSource;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.isTermVectorsResultWithFields;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.whereBucketsAreEmpty;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.whereBucketsAreEmptyOrZero;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.whereBucketsEqual;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.whereDocumentSourceEquals;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.whereFieldsEquals;
import static org.opensearch.test.framework.matcher.RestDocumentMatchers.whereNonEmptyBucketsExist;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * This int tests defines a test matrix using parameters and methods to test FLS and field masking:
 * <ul>
 * <li>On the parameter level, different users with different FLS/FM configs are used for test execution. The user are associated with test oracles which help validating the test results.
 * <li>On the test method level, different operations (get, search, aggregation, terms vectors) are used with the defined users.
 * </ul>
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class FlsFmIntegrationTests {

    static final TestData TEST_DATA = TestData.DEFAULT;
    static final TestData.TestDocuments TEST_DOCUMENTS = TEST_DATA.documents();
    static final TestIndex TEST_INDEX = TestIndex.name("test_index").setting("index.number_of_shards", 5).data(TEST_DATA).build();
    static final String FIELD_MASKING_SALT = "mytestsaresalted";
    static byte[] FIELD_MASKING_SALT_BYTES = FIELD_MASKING_SALT.getBytes(StandardCharsets.UTF_8);

    static final TestSecurityConfig.User.MetadataKey<TestData.DocumentTransformer> DOC_WITH_FLS_FM_APPLIED =
        new TestSecurityConfig.User.MetadataKey<>("doc_with_fls_fm_applied", TestData.DocumentTransformer.class);

    /**
     * A predicate assigned to a user that determines whether a field can be searched by this user.
     * Fields protected by FLS and field masking cannot be searched.
     */
    static final TestSecurityConfig.User.MetadataKey<FieldNamePredicate> FIELD_IS_SEARCHABLE = new TestSecurityConfig.User.MetadataKey<>(
        "field_is_searchable",
        FieldNamePredicate.class
    );

    /**
     * A predicate assigned to a user that determines whether a field can be searched by this user.
     * Fields protected by FLS cannot be aggregated. However, fields protected by field masking can be aggregated.
     */
    static final TestSecurityConfig.User.MetadataKey<FieldNamePredicate> FIELD_IS_AGGREGABLE = new TestSecurityConfig.User.MetadataKey<>(
        "field_is_aggregable",
        FieldNamePredicate.class
    );

    interface Users {
        TestSecurityConfig.User FULL = new TestSecurityConfig.User("full").description("May see everything")
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc)
            .reference(FIELD_IS_SEARCHABLE, field -> true)
            .reference(FIELD_IS_AGGREGABLE, field -> true);

        TestSecurityConfig.User FLS_EXCLUSION_ON_TEXT = new TestSecurityConfig.User("fls_exclusion_on_text").description(
            "May not see attr_text_1"
        )
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .fls("~attr_text_1")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.withoutAttributes("attr_text_1"))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_text_1"))
            .reference(FIELD_IS_AGGREGABLE, field -> !field.startsWith("attr_text_1"));

        TestSecurityConfig.User FLS_EXCLUSION_ON_STORED_FIELD = new TestSecurityConfig.User("fls_exclusion_on_stored_field").description(
            "May not see attr_text_stored"
        )
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .fls("~attr_text_stored")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.withoutAttributes("attr_text_stored"))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_text_stored"))
            .reference(FIELD_IS_AGGREGABLE, field -> !field.startsWith("attr_text_stored"));

        TestSecurityConfig.User FLS_INCLUSION_ON_TEXT = new TestSecurityConfig.User("fls_inclusion_on_text").description(
            "May only see attr_text_1"
        )
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .fls("attr_text_1")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.withOnlyAttributes("attr_text_1"))
            .reference(FIELD_IS_SEARCHABLE, field -> field.startsWith("attr_text_1"))
            .reference(FIELD_IS_AGGREGABLE, field -> field.startsWith("attr_text_1"));

        TestSecurityConfig.User FLS_EXCLUSION_ON_NESTED_ATTRIBUTE = new TestSecurityConfig.User("fls_exclusion_on_nested_attribute")
            .description("May not see attr_object.obj_attr_text_1")
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .fls("~attr_object.obj_attr_text_1")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.withoutAttributes("attr_object.obj_attr_text_1"))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_object.obj_attr_text_1"))
            .reference(FIELD_IS_AGGREGABLE, field -> !field.startsWith("attr_object.obj_attr_text_1"));

        TestSecurityConfig.User FLS_EXCLUSION_ON_OBJECT_ATTRIBUTE = new TestSecurityConfig.User("fls_exclusion_on_object_attribute")
            .description("May not see attr_object")
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .fls("~attr_object")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.withoutAttributes("attr_object"))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_object"))
            .reference(FIELD_IS_AGGREGABLE, field -> !field.startsWith("attr_object"));

        TestSecurityConfig.User FLS_EXCLUSION_ON_INTEGER_NUMBER = new TestSecurityConfig.User("fls_exclusion_on_integer_number")
            .description("May not see attr_int")
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .fls("~attr_int")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.withoutAttributes("attr_int"))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_int"))
            .reference(FIELD_IS_AGGREGABLE, field -> !field.startsWith("attr_int"));

        TestSecurityConfig.User FLS_EXCLUSION_ON_IP = new TestSecurityConfig.User("fls_exclusion_on_ip").description(
            "May not see source_ip"
        )
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .fls("~source_ip")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.withoutAttributes("source_ip"))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("source_ip"))
            .reference(FIELD_IS_AGGREGABLE, field -> !field.startsWith("source_ip"));

        TestSecurityConfig.User MASKING_ON_TEXT = new TestSecurityConfig.User("masking_on_text").description(
            "May see attr_text_1 only masked"
        )
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .maskedFields("attr_text_1")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.applyFieldTransform("attr_text_1", blake2b(FIELD_MASKING_SALT_BYTES)))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_text_1"))
            .reference(FIELD_IS_AGGREGABLE, field -> true);

        TestSecurityConfig.User MASKING_ON_KEYWORD = new TestSecurityConfig.User("masking_on_keyword").description(
            "May see attr_keyword only masked"
        )
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .maskedFields("attr_keyword", "attr_keyword_doc_values_disabled")
                    .on(TEST_INDEX)
            )
            .reference(
                DOC_WITH_FLS_FM_APPLIED,
                doc -> doc.applyFieldTransform("attr_keyword", blake2b(FIELD_MASKING_SALT_BYTES))
                    .applyFieldTransform("attr_keyword_doc_values_disabled", blake2b(FIELD_MASKING_SALT_BYTES))
            )
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_keyword"))
            .reference(FIELD_IS_AGGREGABLE, field -> true);

        TestSecurityConfig.User MASKING_ON_STORED_FIELD = new TestSecurityConfig.User("masking_on_stored_field").description(
            "May see attr_text_stored only masked"
        )
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .maskedFields("attr_text_stored")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.applyFieldTransform("attr_text_stored", blake2b(FIELD_MASKING_SALT_BYTES)))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_text_stored"))
            .reference(FIELD_IS_AGGREGABLE, field -> true);

        TestSecurityConfig.User MASKING_ON_IP = new TestSecurityConfig.User("masking_on_ip").description("May see source_ip only masked")
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .maskedFields("source_ip")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.applyFieldTransform("source_ip", blake2b(FIELD_MASKING_SALT_BYTES)))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("source_ip"))
            .reference(FIELD_IS_AGGREGABLE, field -> true);

        TestSecurityConfig.User MASKING_ON_BINARY = new TestSecurityConfig.User("masking_on_binary").description(
            "May see attr_binary only masked"
        )
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .maskedFields("attr_binary")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.applyFieldTransform("attr_binary", blake2b(FIELD_MASKING_SALT_BYTES)))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_binary"))
            .reference(FIELD_IS_AGGREGABLE, field -> true);

        List<TestSecurityConfig.User> ALL = Arrays.asList(
            FULL,
            FLS_EXCLUSION_ON_TEXT,
            FLS_INCLUSION_ON_TEXT,
            FLS_EXCLUSION_ON_STORED_FIELD,
            FLS_EXCLUSION_ON_NESTED_ATTRIBUTE,
            FLS_EXCLUSION_ON_OBJECT_ATTRIBUTE,
            FLS_EXCLUSION_ON_INTEGER_NUMBER,
            FLS_EXCLUSION_ON_IP,
            MASKING_ON_TEXT,
            MASKING_ON_KEYWORD,
            MASKING_ON_STORED_FIELD,
            MASKING_ON_IP,
            MASKING_ON_BINARY
        );

    }

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .plugin(MapperSizePlugin.class)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(Users.ALL)
        .indices(TEST_INDEX)
        .nodeSettings(ImmutableMap.of("plugins.security.compliance.salt", FIELD_MASKING_SALT))
        .build();

    @Test
    public void get() {
        TestData.TestDocument testDocument = TEST_DATA.anyDocument();
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_doc/" + testDocument.id());
            assertThat(response, isOk());
            assertThat(response, hasSource(testDocument.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))));
        }
    }

    @Test
    public void search_source() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_search");
            assertThat(response, isOk());
            assertThat(
                response,
                hasSearchHits(whereDocumentSourceEquals(TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))))
            );
        }
    }

    @Test
    public void search_fields() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "fields": [
                    "attr_text_1",
                    "attr_text_2",
                    "attr_binary",
                    "attr_int",
                    "source_ip",
                    "attr_object.obj_attr_text_1",
                    "attr_object.obj_attr_object.obj_obj_attr_text"
                  ]
                }""");
            assertThat(response, isOk());
            assertThat(
                response,
                hasSearchHits(
                    whereFieldsEquals(
                        TEST_DOCUMENTS.applyTransform(
                            user.reference(DOC_WITH_FLS_FM_APPLIED),
                            d -> d.withOnlyAttributes(
                                "attr_text_1",
                                "attr_text_2",
                                "attr_binary",
                                "attr_int",
                                "source_ip",
                                "attr_object.obj_attr_text_1",
                                "attr_object.obj_attr_object.obj_obj_attr_text"
                            )
                        )
                    )
                )
            );
        }
    }

    @Test
    public void search_docValueFields() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "docvalue_fields": [
                    "attr_text_1.keyword",
                    "attr_text_2.keyword",
                    "attr_int",
                    "source_ip"
                  ]
                }""");
            System.out.println(response.getBody());
            assertThat(response, isOk());
            assertThat(
                response,
                hasSearchHits(
                    whereFieldsEquals(
                        TEST_DOCUMENTS.applyTransform(
                            user.reference(DOC_WITH_FLS_FM_APPLIED),
                            d -> d.withOnlyAttributes("attr_text_1", "attr_text_2", "attr_int", "source_ip")
                        )
                    )
                )
            );
        }
    }

    @Test
    public void search_storedFields() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "stored_fields": [
                    "attr_text_stored"
                  ],
                  "fields": [
                    "attr_text_1"
                  ]
                }""");
            System.out.println(response.getBody());
            assertThat(response, isOk());
            assertThat(
                response,
                hasSearchHits(
                    whereFieldsEquals(
                        TEST_DOCUMENTS.applyTransform(
                            user.reference(DOC_WITH_FLS_FM_APPLIED),
                            d -> d.withOnlyAttributes("attr_text_stored", "attr_text_1")
                        )
                    )
                )
            );
        }
    }

    @Test
    public void search_aggregation_keywordAttribute() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "aggs": {
                    "keyword_agg": {
                      "terms": {
                        "field": "attr_text_1.keyword"
                      }
                    }
                  }
                }""");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_AGGREGABLE).test("attr_text_1")) {
                assertThat(
                    response,
                    hasAggregation(
                        "keyword_agg",
                        whereBucketsEqual(TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED)).aggregation("attr_text_1"))
                    )
                );
            } else {
                assertThat(response, hasAggregation("keyword_agg", whereBucketsAreEmpty()));
            }
        }
    }

    @Test
    public void search_aggregation_explicitKeywordAttribute() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "aggs": {
                    "keyword_agg": {
                      "terms": {
                        "field": "attr_keyword"
                      }
                    }
                  }
                }""");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_AGGREGABLE).test("attr_keyword")) {
                assertThat(response, hasAggregation("keyword_agg", whereBucketsEqual(TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED)).aggregation("attr_keyword"))));
            } else {
                assertThat(response, hasAggregation("keyword_agg", whereBucketsAreEmpty()));
            }
        }
    }

    @Test
    public void search_aggregation_ip() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "aggs": {
                    "ip_agg": {
                      "ip_range": {
                        "field": "source_ip",
                        "ranges": [
                           { "to": "103.105.0.0" },
                           { "from": "103.105.0.0" }
                        ]
                      }
                    }
                  }
                }""");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_AGGREGABLE).test("source_ip")) {
                assertThat(response, hasAggregation("ip_agg", whereNonEmptyBucketsExist()));
            } else {
                assertThat(response, hasAggregation("ip_agg", whereBucketsAreEmptyOrZero()));
            }
        }
    }

    @Test
    public void search_aggregation_binary() {
        if (user == Users.MASKING_ON_BINARY) {
            // Field masking on a binary field produces an error 500. Skip this until it is fixed.
            // This exception is encountered:
            // Caused by: java.lang.ArrayIndexOutOfBoundsException: arraycopy: last source index 100 out of bounds for byte[64]
            // at java.lang.System.arraycopy(Native Method) ~[?:?]
            // at org.apache.lucene.util.BytesRefBuilder.copyBytes(BytesRefBuilder.java:106) ~[lucene-core-10.1.0.jar:10.1.0
            // 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.apache.lucene.util.BytesRefBuilder.copyBytes(BytesRefBuilder.java:114) ~[lucene-core-10.1.0.jar:10.1.0
            // 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at
            // org.opensearch.search.aggregations.bucket.terms.MapStringTermsAggregator$ValuesSourceCollectorSource$1.collect(MapStringTermsAggregator.java:229)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.opensearch.search.aggregations.LeafBucketCollector.collect(LeafBucketCollector.java:123)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.apache.lucene.search.MultiCollector$MultiLeafCollector.collect(MultiCollector.java:221)
            // ~[lucene-core-10.1.0.jar:10.1.0 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.apache.lucene.search.MatchAllDocsQuery$1$1$1.score(MatchAllDocsQuery.java:61) ~[lucene-core-10.1.0.jar:10.1.0
            // 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.opensearch.search.internal.CancellableBulkScorer.score(CancellableBulkScorer.java:71)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.opensearch.search.internal.ContextIndexSearcher.searchLeaf(ContextIndexSearcher.java:356)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.opensearch.search.internal.ContextIndexSearcher.search(ContextIndexSearcher.java:305)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.opensearch.search.internal.ContextIndexSearcher.search(ContextIndexSearcher.java:269)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.opensearch.search.query.QueryPhase.searchWithCollector(QueryPhase.java:355)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            return;
        }

        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "aggs": {
                    "binary_agg": {
                      "terms": {
                        "field": "attr_binary",
                        "min_doc_count": 10
                      }
                    }
                  }
                }""");
            assertThat(response, isOk());
            System.out.println(response.getBody());
            if (user.reference(FIELD_IS_AGGREGABLE).test("attr_binary")) {
                assertThat(response, hasAggregation("binary_agg", whereBucketsEqual(TEST_DOCUMENTS.aggregation("attr_binary", 10))));
            } else {
                assertThat(response, hasAggregation("binary_agg", whereBucketsAreEmpty()));
            }
        }
    }

    @Test
    public void search_abilityToSearch_textAttribute() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_search?q=attr_text_2:coffee");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_text_2")) {
                assertThat(
                    response,
                    hasSearchHits(whereDocumentSourceEquals(TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))))
                );
            } else {
                assertThat(response, hasSearchHits(emptyHits()));
            }
        }
    }

    @Test
    public void search_abilityToSearch_keywordAttribute() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_search?q=attr_text_1.keyword:dept_a_1");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_text_1")) {
                assertThat(
                    response,
                    hasSearchHits(whereDocumentSourceEquals(TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))))
                );
            } else {
                assertThat(response, hasSearchHits(emptyHits()));
            }
        }
    }

    @Test
    public void search_abilityToSearch_keywordAttribute_prefixQuery() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "query": {
                    "prefix": {
                      "attr_text_1.keyword": "dept_a"
                    }
                  }
                }""");
            System.out.println(response.getBody());
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_text_1")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(d -> d.attrText1().startsWith("dept_a"))
                                .applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))
                        )
                    )
                );
            } else {
                assertThat(response, hasSearchHits(emptyHits()));
            }
        }
    }

    @Test
    public void search_abilityToSearch_explicitKeywordAttribute() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_search?q=attr_keyword.keyword:dept_a_1");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_keyword")) {
                assertThat(
                    response,
                    hasSearchHits(whereDocumentSourceEquals(TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))))
                );
            } else {
                assertThat(response, hasSearchHits(emptyHits()));
            }
        }
    }

    @Test
    public void search_abilityToSearch_explicitKeywordAttribute_rangeQuery() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "query": {
                    "range": {
                      "attr_keyword_doc_values_disabled": {
                        "gte": "dept_a",
                        "lte": "dept_c"
                      }
                    }
                  }
                }""");
            System.out.println(response.getBody());
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_keyword_doc_values_disabled")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(
                                d -> d.attrKeywordDocValuesDisabled().startsWith("dept_a")
                                    || d.attrKeywordDocValuesDisabled().startsWith("dept_b")
                                    || d.attrKeywordDocValuesDisabled().startsWith("dept_c")
                            ).applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))
                        )
                    )
                );
            } else {
                assertThat(response, hasSearchHits(emptyHits()));
            }
        }
    }

    @Test
    public void search_abilityToSearch_numericRange() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(
                TEST_INDEX.name() + "/_search?q=" + URLEncoder.encode("attr_int:[5000 TO 9000]", StandardCharsets.US_ASCII)
            );
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_int")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(d -> d.attrInt() >= 5000 && d.attrInt() <= 9000)
                                .applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))
                        )
                    )
                );
            } else {
                assertThat(response, hasSearchHits(emptyHits()));
            }
        }
    }

    /**
     * The exists query internally operates on the _field_names field which gets special treatment in DlsFlsFilterLeafReader
     */
    @Test
    public void search_abilityToSearch_exists() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                  "query": {
                    "exists": {
                      "field": "attr_text_doc_values_disabled_nullable"
                    }
                  }
                }""");
            assertThat(response, isOk());
            System.out.println(response.getBody());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_text_doc_values_disabled_nullable")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(d -> d.content().containsKey("attr_text_doc_values_disabled_nullable"))
                                .applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))
                        )
                    )
                );
            } else {
                assertThat(response, hasSearchHits(emptyHits()));
            }
        }
    }

    @Test
    public void search_sortBy_explicitKeywordAttribute() {
        if (user == Users.MASKING_ON_KEYWORD) {
            // Sorting by a masked field produces an error 500. Skip this until this is fixed.
            // This exception is encountered:
            // Caused by: java.lang.NullPointerException: Cannot invoke "org.apache.lucene.index.Terms.iterator()" because the return value
            // of "org.apache.lucene.index.LeafReader.terms(String)" is null
            // at org.apache.lucene.search.comparators.TermOrdValComparator$CompetitiveIterator.init(TermOrdValComparator.java:573)
            // ~[lucene-core-10.1.0.jar:10.1.0 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.apache.lucene.search.comparators.TermOrdValComparator$CompetitiveIterator.update(TermOrdValComparator.java:546)
            // ~[lucene-core-10.1.0.jar:10.1.0 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at
            // org.apache.lucene.search.comparators.TermOrdValComparator$TermOrdValLeafComparator.updateCompetitiveIterator(TermOrdValComparator.java:458)
            // ~[lucene-core-10.1.0.jar:10.1.0 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at
            // org.apache.lucene.search.comparators.TermOrdValComparator$TermOrdValLeafComparator.setHitsThresholdReached(TermOrdValComparator.java:285)
            // ~[lucene-core-10.1.0.jar:10.1.0 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.apache.lucene.search.MultiLeafFieldComparator.setHitsThresholdReached(MultiLeafFieldComparator.java:98)
            // ~[lucene-core-10.1.0.jar:10.1.0 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.apache.lucene.search.TopFieldCollector$TopFieldLeafCollector.countHit(TopFieldCollector.java:83)
            // ~[lucene-core-10.1.0.jar:10.1.0 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.apache.lucene.search.TopFieldCollector$SimpleFieldCollector$1.collect(TopFieldCollector.java:200)
            // ~[lucene-core-10.1.0.jar:10.1.0 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.apache.lucene.search.Weight$DefaultBulkScorer.scoreRange(Weight.java:324) ~[lucene-core-10.1.0.jar:10.1.0
            // 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.apache.lucene.search.Weight$DefaultBulkScorer.score(Weight.java:264) ~[lucene-core-10.1.0.jar:10.1.0
            // 884954006de769dc43b811267230d625886e6515 - 2024-12-17 16:15:44]
            // at org.opensearch.search.internal.CancellableBulkScorer.score(CancellableBulkScorer.java:71)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.opensearch.search.internal.ContextIndexSearcher.searchLeaf(ContextIndexSearcher.java:356)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.opensearch.search.internal.ContextIndexSearcher.search(ContextIndexSearcher.java:305)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.opensearch.search.internal.ContextIndexSearcher.search(ContextIndexSearcher.java:269)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            // at org.opensearch.search.query.QueryPhase.searchWithCollector(QueryPhase.java:355)
            // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
            return;
        }

        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search", """
                {
                    "sort" : [
                       { "attr_keyword": "asc"},
                       { "attr_long" : "desc" }
                    ]
                }""");

            System.out.println(response.getBody());
            // TODO: Assert for case where attr_keyword is hidden by FLS an assertion that no values are exposed in the sort attribute of
            // hits
            assertThat(response, isOk());
            assertThat(
                response,
                hasSearchHits(whereDocumentSourceEquals(TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))))
            );
        }
    }

    @Ignore
    @Test
    public void termVectors() {
        // Term vectors on FLS/FM protected documents fail with an internal OpenSearch assertion error
        // java.lang.AssertionError: null
        // at __randomizedtesting.SeedInfo.seed([36B4FFBCDDE3E188]:0) ~[?:?]
        // at org.opensearch.action.termvectors.TermVectorsWriter.writeTermWithDocsAndPos(TermVectorsWriter.java:213)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.action.termvectors.TermVectorsWriter.setFields(TermVectorsWriter.java:139)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.action.termvectors.TermVectorsResponse.setFields(TermVectorsResponse.java:414)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.index.termvectors.TermVectorsService.getTermVectors(TermVectorsService.java:161)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.index.termvectors.TermVectorsService.getTermVectors(TermVectorsService.java:97)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.action.termvectors.TransportTermVectorsAction.shardOperation(TransportTermVectorsAction.java:148)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.action.termvectors.TransportTermVectorsAction.shardOperation(TransportTermVectorsAction.java:62)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at
        // org.opensearch.action.support.single.shard.TransportSingleShardAction.lambda$asyncShardOperation$0(TransportSingleShardAction.java:131)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.action.ActionRunnable.lambda$supply$0(ActionRunnable.java:74)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.action.ActionRunnable$2.doRun(ActionRunnable.java:89)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.common.util.concurrent.ThreadContext$ContextPreservingAbstractRunnable.doRun(ThreadContext.java:994)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at org.opensearch.common.util.concurrent.AbstractRunnable.run(AbstractRunnable.java:52)
        // ~[opensearch-3.0.0-beta1-SNAPSHOT.jar:3.0.0-beta1-SNAPSHOT]
        // at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144) ~[?:?]
        // at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:642) ~[?:?]
        // at java.base/java.lang.Thread.run(Thread.java:1583) [?:?]

        TestData.TestDocument testDocument = TEST_DATA.anyDocument();

        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(
                TEST_INDEX.name() + "/_termvectors/" + testDocument.id() + "?term_statistics=true&payloads=true&fields=*"
            );
            System.out.println(response.getBody());
            assertThat(response, isOk());
            assertThat(
                response,
                isTermVectorsResultWithFields(correspondingToDocument(testDocument.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))))
            );
        }
    }

    TestSecurityConfig.User user;

    public FlsFmIntegrationTests(TestSecurityConfig.User user) {
        this.user = user;
    }

    @ParametersFactory(shuffle = false)
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();

        for (TestSecurityConfig.User user : Users.ALL) {
            result.add(new Object[] { user });
        }

        return result;
    }

    @FunctionalInterface
    interface FieldNamePredicate extends Predicate<String> {

    }

    static Function<Object, Object> blake2b(byte[] salt) {
        return (value) -> {
            if (!(value instanceof String stringValue)) {
                return value;
            }
            byte[] stringValueBytes = stringValue.getBytes(StandardCharsets.UTF_8);
            Blake2b hash = new Blake2b(null, 32, salt, null);
            hash.update(stringValueBytes, 0, stringValueBytes.length);
            final byte[] out = new byte[hash.getDigestSize()];
            hash.digest(out, 0);
            return new String(Hex.encode(out), StandardCharsets.UTF_8);
        };
    }

}
