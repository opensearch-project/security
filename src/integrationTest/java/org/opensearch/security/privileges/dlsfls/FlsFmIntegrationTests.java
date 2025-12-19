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

import com.google.common.collect.ImmutableMap;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.bouncycastle.util.encoders.Hex;

import org.opensearch.plugin.mapper.MapperSizePlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestData;
import org.opensearch.test.framework.data.TestIndex;

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
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isInternalServerError;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * This int tests defines a test matrix using parameters and methods to test FLS and field masking:
 * <ul>
 * <li>On the parameter level, different users with different FLS/FM configs are used for test execution. The user are associated with test oracles which help validating the test results.
 * <li>On the test method level, different operations (get, search, aggregation, terms vectors) are used with the defined users.
 * </ul>
 */
@RunWith(Parameterized.class)
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

        TestSecurityConfig.User MASKING_ON_GEO_POINT_STRING = new TestSecurityConfig.User("masking_on_geo_point_string").description(
            "May see geo_point_string only masked"
        )
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .maskedFields("attr_geo_point_string")
                    .on(TEST_INDEX)
            )
            .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc.applyFieldTransform("attr_geo_point_string", blake2b(FIELD_MASKING_SALT_BYTES)))
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_geo_point_string"))
            .reference(FIELD_IS_AGGREGABLE, field -> true);

        TestSecurityConfig.User MASKING_ON_GEO_POINT_STRING_STORED = new TestSecurityConfig.User("masking_on_geo_point_string_stored")
            .description("May see geo_point_string_stored only masked")
            .roles(
                new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro")
                    .indexPermissions("read")
                    .maskedFields("attr_geo_point_string_stored")
                    .on(TEST_INDEX)
            )
            .reference(
                DOC_WITH_FLS_FM_APPLIED,
                doc -> doc.applyFieldTransform("attr_geo_point_string_stored", blake2b(FIELD_MASKING_SALT_BYTES))
            )
            .reference(FIELD_IS_SEARCHABLE, field -> !field.startsWith("attr_geo_point_string_stored"))
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
            MASKING_ON_GEO_POINT_STRING,
            MASKING_ON_GEO_POINT_STRING_STORED,
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

    /**
     * This test has two main objectives. It ensures:
     * - that the document is only found when the DLS rule allows it. This gives coverage for DlsFlsFilterLeafReader.DlsGetEvaluator
     * - that the document sources in a search response are properly filtered according to FLS/FM rules. This gives coverage for FlsStoredFieldVisitor.binaryField() and FlsDocumentFilter
     */
    @Test
    public void get() {
        TestData.TestDocument testDocument = TEST_DATA.anyDocument();
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_doc/" + testDocument.id());
            assertThat(response, isOk());
            assertThat(response, hasSource(testDocument.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))));
        }
    }

    /**
     * This test has two main objectives. It ensures:
     * - that the returned documents only contain allowed documents according to DLS rules. This gives coverage for DlsFlsValveImpl.handleSearchContext() (via a SearchOperationListener)
     * - that the document sources in a search response are properly filtered according to FLS/FM rules. This gives coverage for FlsStoredFieldVisitor.binaryField() and FlsDocumentFilter
     */
    @Test
    public void search_source() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_search?size=1000");
            assertThat(response, isOk());
            assertThat(
                response,
                hasSearchHits(whereDocumentSourceEquals(TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))))
            );
        }
    }

    /**
     * This test ensures that fields returned in the search response are filtered according to FLS/FM rules.
     * This gives coverage for DlsFlsFilterLeafReader.getFieldInfos().
     */
    @Test
    public void search_fields() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search?size=1000", """
                {
                  "fields": [
                    "attr_text_1",
                    "attr_text_2",
                    "attr_binary",
                    "attr_int",
                    "source_ip",
                    "attr_geo_point_string",
                    "attr_object.obj_attr_text_1",
                    "attr_object.obj_attr_object.obj_obj_attr_text"
                  ]
                }""");
            if (user == Users.MASKING_ON_IP) {
                // OpenSearch will try to parse the hashed IP address for retrieving the fields values;
                // as the hashed address is not a valid IP address, this wil fail.
                // Note: The 400 Bad Request REST response is semantically not correct, it's just the weird way OpenSearch handles
                // IllegalArgumentExceptions
                assertThat(response, isBadRequest("/error/root_cause/0/reason", "is not an IP string literal"));
            } else if (user == Users.MASKING_ON_GEO_POINT_STRING) {
                // Also for geo points, parsing the hashed geo data will fail.
                assertThat(response, isBadRequest("/error/root_cause/0/reason", "unsupported symbol"));
            } else {
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
                                    "attr_geo_point_string",
                                    "attr_object.obj_attr_text_1",
                                    "attr_object.obj_attr_object.obj_obj_attr_text"
                                )
                            )
                        )
                    )
                );
            }
        }
    }

    /**
     * This test ensures that docvalue_fields returned in the search response are filtered according to FLS/FM rules.
     * This gives coverage for the get*DocValues() methods in DlsFlsFilterLeafReader.
     */
    @Test
    public void search_docValueFields() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search?size=1000", """
                {
                  "docvalue_fields": [
                    "attr_text_1.keyword",
                    "attr_text_2.keyword",
                    "attr_int",
                    "source_ip",
                    "attr_geo_point_string"
                  ]
                }""");
            if (user == Users.MASKING_ON_IP) {
                // Also here: OpenSearch wont be able to parse a masked doc value. The exception types do not really matter.
                assertThat(response, isBadRequest("/error/root_cause/0/type", "illegal_argument_exception"));
            } else if (user == Users.MASKING_ON_GEO_POINT_STRING) {
                assertThat(response, isInternalServerError("/error/root_cause/0/type", "illegal_state_exception"));
            } else {
                assertThat(response, isOk());
                assertThat(
                    response,
                    hasSearchHits(
                        whereFieldsEquals(
                            TEST_DOCUMENTS.applyTransform(
                                user.reference(DOC_WITH_FLS_FM_APPLIED),
                                d -> d.withOnlyAttributes("attr_text_1", "attr_text_2", "attr_int", "source_ip", "attr_geo_point_string")
                            )
                        )
                    )
                );
            }
        }
    }

    /**
     * This test ensures that stored fields returned in the search response are filtered according to FLS/FM rules.
     * This gives coverage for all *field methods in FlsStoredFieldVisitor (via the different data types of the fields).
     */
    @Test
    public void search_storedFields() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search?size=1000", """
                {
                  "stored_fields": [
                    "attr_text_stored"
                  ],
                  "fields": [
                    "attr_text_1"
                  ]
                }""");
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

    /**
     * This test has two main objectives. It ensures for string (keyword) fields:
     * - that an empty aggregation is returned when the attribute to be aggregated on is not allowed by FLS.
     * - that the aggregation has properly masked bucket keys when the attribute to be aggregated on is protected by field masking.
     * This gives coverage for the *SortedSetDocValues methods in DlsFlsFilterLeafReader
     */
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

    /**
     * This test has two main objectives. It ensures for string (keyword) fields:
     * - that an empty aggregation is returned when the attribute to be aggregated on is not allowed by FLS.
     * - that the aggregation has properly masked bucket keys when the attribute to be aggregated on is protected by field masking.
     * This gives coverage for the *SortedSetDocValues methods in DlsFlsFilterLeafReader
     */
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
                assertThat(
                    response,
                    hasAggregation(
                        "keyword_agg",
                        whereBucketsEqual(
                            TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED)).aggregation("attr_keyword")
                        )
                    )
                );
            } else {
                assertThat(response, hasAggregation("keyword_agg", whereBucketsAreEmpty()));
            }
        }
    }

    /**
     * This test replicates the above aggregation tests for fields of type IP.
     * This gives coverage for the *SortedSetDocValues methods in DlsFlsFilterLeafReader
     */
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
    public void search_abilityToSearch_nestedAttribute() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(
                TEST_INDEX.name() + "/_search?q=attr_object.obj_attr_text_1:dept_a_1&size=1000"
            );
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_object.obj_attr_text_1")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(d -> "dept_a_1".equals(d.getAttributeByPath("attr_object", "obj_attr_text_1")))
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
     * This test replicates the above aggregation tests for fields of type binary.
     * This gives coverage for the *BinaryDocValues methods in DlsFlsFilterLeafReader
     */
    @Test
    public void search_aggregation_binary() {
        if (user == Users.MASKING_ON_BINARY) {
            // Field masking on a binary field produces an error 500. Skip this until it is fixed.
            // Issue: https://github.com/opensearch-project/security/issues/5253
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
            if (user.reference(FIELD_IS_AGGREGABLE).test("attr_binary")) {
                assertThat(response, hasAggregation("binary_agg", whereBucketsEqual(TEST_DOCUMENTS.aggregation("attr_binary", 10))));
            } else {
                assertThat(response, hasAggregation("binary_agg", whereBucketsAreEmpty()));
            }
        }
    }

    /**
     * This method verifies that search queries are only possible on fields if they are not protected by FLS/FM.
     * This gives coverage for the terms() method in DlsFlsFilterLeafReader
     */
    @Test
    public void search_abilityToSearch_textAttribute() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_search?q=attr_text_2:coffee&size=1000");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_text_2")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(d -> d.attrText2().contains("coffee"))
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
     * Same test as before, but verfies keyword fields
     */
    @Test
    public void search_abilityToSearch_keywordAttribute() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_search?q=attr_text_1.keyword:dept_a_1&size=1000");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_text_1")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(d -> d.attrText1().equals("dept_a_1"))
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
    public void search_abilityToSearch_keywordAttribute_prefixQuery() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search?size=1000", """
                {
                  "query": {
                    "prefix": {
                      "attr_text_1.keyword": "dept_a"
                    }
                  }
                }""");
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
            TestRestClient.HttpResponse response = client.get(TEST_INDEX.name() + "/_search?q=attr_keyword:dept_a_1&size=1000");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_keyword")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(d -> d.attrKeyword().equals("dept_a_1"))
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
    public void search_abilityToSearch_explicitKeywordAttribute_rangeQuery() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search?size=1000", """
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
                TEST_INDEX.name() + "/_search?q=" + URLEncoder.encode("attr_int:[5000 TO 9000]", StandardCharsets.US_ASCII) + "&size=1000"
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

    @Test
    public void search_abilityToSearch_ip() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search?size=1000", """
                {
                  "query": {
                    "term": {
                      "source_ip": "101.0.0.0/8"
                    }
                  }
                }""");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("source_ip")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(d -> d.sourceIp().startsWith("101."))
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
    public void search_abilityToSearch_geoPoint() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search?size=1000", """
                {
                  "query": {
                    "geo_bounding_box": {
                      "attr_geo_point_string": {
                        "top_left": {
                          "lat": 90,
                          "lon": 10
                        },
                        "bottom_right": {
                          "lat": 10,
                          "lon": 99.9999999
                        }
                      }
                    }
                  }
                }""");
            assertThat(response, isOk());
            if (user.reference(FIELD_IS_SEARCHABLE).test("attr_geo_point_string")) {
                assertThat(
                    response,
                    hasSearchHits(
                        whereDocumentSourceEquals(
                            TEST_DOCUMENTS.where(d -> d.attrGeoPointString().matches("[1-9][0-9]\\.[0-9]+,\\s*[1-9][0-9]\\.[0-9]+"))
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
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search?size=1000", """
                {
                  "query": {
                    "exists": {
                      "field": "attr_text_doc_values_disabled_nullable"
                    }
                  }
                }""");
            assertThat(response, isOk());
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
            // Issue: https://github.com/opensearch-project/security/issues/5254
            return;
        }

        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(TEST_INDEX.name() + "/_search?size=1000", """
                {
                    "sort" : [
                       { "attr_keyword": "asc"},
                       { "attr_long" : "desc" }
                    ]
                }""");

            // TODO: Assert for case where attr_keyword is hidden by FLS an assertion that no values are exposed in the sort attribute of
            // hits
            assertThat(response, isOk());
            assertThat(
                response,
                hasSearchHits(whereDocumentSourceEquals(TEST_DOCUMENTS.applyTransform(user.reference(DOC_WITH_FLS_FM_APPLIED))))
            );
        }
    }

    @Test
    public void termVectors() {
        if (user == Users.MASKING_ON_TEXT
            || user == Users.MASKING_ON_KEYWORD
            || user == Users.MASKING_ON_BINARY
            || user == Users.MASKING_ON_IP
            || user == Users.MASKING_ON_STORED_FIELD) {
            // Term vectors on field masking protected documents fail with an internal OpenSearch assertion error
            // Issue: https://github.com/opensearch-project/security/issues/5255
            return;
        }
        TestData.TestDocument testDocument = TEST_DATA.anyDocument();

        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(
                TEST_INDEX.name() + "/_termvectors/" + testDocument.id() + "?term_statistics=true&payloads=true&fields=*"
            );
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

    @Parameters(name = "user={0}")
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
