/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security;

import java.util.List;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.index.query.QueryBuilders;
import org.opensearch.indices.TermsLookup;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.transport.client.Client;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * Tests that FLS and Field Masking restrictions are NOT lifted when an index appears in the
 * DocumentAllowList due to a terms_lookup DLS rule (which adds specific document IDs, not "*").
 *
 * Only Dashboards multi-tenancy (which adds wildcard "*" entries) should cause FLS/FM to be lifted.
 */
public class FlsTermsLookupBypassTests {

    static final String SENSITIVE_INDEX = "sensitive-data";
    static final String TERM_LOOKUP_INDEX = "term-lookup-source";
    static final String TERMS_DOC_ID = "lookup_doc_1";
    static final String TERM_PATH = "allowed_values";

    static final String FIELD_NAME = "name";
    static final String FIELD_SSN = "ssn";
    static final String FIELD_SALARY = "salary";
    static final String FIELD_DEPARTMENT = "department";

    private static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    /**
     * User with:
     * - FLS on SENSITIVE_INDEX: can only see "name" and "department" (ssn and salary hidden)
     * - DLS with terms_lookup on TERM_LOOKUP_INDEX referencing SENSITIVE_INDEX
     * - Read access to both indices
     */
    private static final User FLS_USER_WITH_TLQ_DLS = new User("fls_tlq_user").roles(
        new Role("fls_on_sensitive").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .fls(FIELD_NAME, FIELD_DEPARTMENT)
            .on(SENSITIVE_INDEX),
        new Role("dls_tlq_on_lookup").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(QueryBuilders.termsLookupQuery("department", new TermsLookup(SENSITIVE_INDEX, TERMS_DOC_ID, TERM_PATH)))
            .on(TERM_LOOKUP_INDEX)
    );

    /**
     * User with field masking on SENSITIVE_INDEX and DLS terms_lookup on TERM_LOOKUP_INDEX.
     */
    private static final User FM_USER_WITH_TLQ_DLS = new User("fm_tlq_user").roles(
        new Role("fm_on_sensitive").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .maskedFields(FIELD_SSN.concat("::/(?<=.{3})./::*"), FIELD_SALARY.concat("::/(?<=.{1})./::*"))
            .on(SENSITIVE_INDEX),
        new Role("dls_tlq_on_lookup_fm").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(QueryBuilders.termsLookupQuery("department", new TermsLookup(SENSITIVE_INDEX, TERMS_DOC_ID, TERM_PATH)))
            .on(TERM_LOOKUP_INDEX)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, FLS_USER_WITH_TLQ_DLS, FM_USER_WITH_TLQ_DLS)
        .build();

    @BeforeClass
    public static void beforeClass() {
        try (Client client = cluster.getInternalNodeClient()) {
            // Index sensitive data
            client.prepareIndex(SENSITIVE_INDEX)
                .setId("1")
                .setRefreshPolicy(IMMEDIATE)
                .setSource(Map.of(FIELD_NAME, "Alice", FIELD_SSN, "123-45-6789", FIELD_SALARY, "150000", FIELD_DEPARTMENT, "engineering"))
                .get();
            client.prepareIndex(SENSITIVE_INDEX)
                .setId("2")
                .setRefreshPolicy(IMMEDIATE)
                .setSource(Map.of(FIELD_NAME, "Bob", FIELD_SSN, "987-65-4321", FIELD_SALARY, "120000", FIELD_DEPARTMENT, "marketing"))
                .get();

            // Index terms lookup document
            client.prepareIndex(TERM_LOOKUP_INDEX)
                .setId(TERMS_DOC_ID)
                .setRefreshPolicy(IMMEDIATE)
                .setSource(Map.of(TERM_PATH, List.of("engineering"), FIELD_DEPARTMENT, "engineering"))
                .get();
            client.prepareIndex(TERM_LOOKUP_INDEX)
                .setId("other_doc")
                .setRefreshPolicy(IMMEDIATE)
                .setSource(Map.of(FIELD_DEPARTMENT, "marketing"))
                .get();
        }
    }

    @Test
    public void flsShouldNotBeBypassedViaMultiIndexSearchWithTermsLookupDls() {
        try (TestRestClient client = cluster.getRestClient(FLS_USER_WITH_TLQ_DLS)) {
            // Multi-index search that triggers terms_lookup, adding SENSITIVE_INDEX to DocumentAllowList
            HttpResponse response = client.get(TERM_LOOKUP_INDEX + "," + SENSITIVE_INDEX + "/_search?pretty");
            assertThat(response, isOk());

            JsonNode hits = response.bodyAsJsonNode().get("hits").get("hits");
            for (JsonNode hit : hits) {
                if (SENSITIVE_INDEX.equals(hit.get("_index").asText())) {
                    JsonNode source = hit.get("_source");
                    // FLS should still be enforced: ssn and salary must NOT be visible
                    assertThat("FLS bypass: ssn field should not be visible but was returned", source.get(FIELD_SSN), nullValue());
                    assertThat("FLS bypass: salary field should not be visible but was returned", source.get(FIELD_SALARY), nullValue());
                    // Allowed fields should still be present
                    assertThat(source.get(FIELD_NAME), not(nullValue()));
                }
            }
        }
    }

    @Test
    public void fieldMaskingShouldNotBeBypassedViaMultiIndexSearchWithTermsLookupDls() {
        try (TestRestClient client = cluster.getRestClient(FM_USER_WITH_TLQ_DLS)) {
            // Multi-index search that triggers terms_lookup, adding SENSITIVE_INDEX to DocumentAllowList
            HttpResponse response = client.get(TERM_LOOKUP_INDEX + "," + SENSITIVE_INDEX + "/_search?pretty");
            assertThat(response, isOk());

            JsonNode hits = response.bodyAsJsonNode().get("hits").get("hits");
            for (JsonNode hit : hits) {
                if (SENSITIVE_INDEX.equals(hit.get("_index").asText())) {
                    JsonNode source = hit.get("_source");
                    if (source.has(FIELD_SSN)) {
                        String ssnValue = source.get(FIELD_SSN).asText();
                        // Field masking should still be applied: SSN should be masked
                        assertThat(
                            "Field masking bypass: SSN should be masked but got: " + ssnValue,
                            ssnValue,
                            not(equalTo("123-45-6789"))
                        );
                        assertThat(
                            "Field masking bypass: SSN should be masked but got: " + ssnValue,
                            ssnValue,
                            not(equalTo("987-65-4321"))
                        );
                    }
                }
            }
        }
    }

    @Test
    public void flsShouldBeEnforcedOnSensitiveIndexAlone() {
        try (TestRestClient client = cluster.getRestClient(FLS_USER_WITH_TLQ_DLS)) {
            // Single-index search on the sensitive index (no terms_lookup trigger)
            HttpResponse response = client.get(SENSITIVE_INDEX + "/_search?pretty");
            assertThat(response, isOk());

            JsonNode hits = response.bodyAsJsonNode().get("hits").get("hits");
            assertThat("Expected results from sensitive index", hits.size(), not(equalTo(0)));
            for (JsonNode hit : hits) {
                JsonNode source = hit.get("_source");
                assertThat("ssn should not be visible with FLS", source.get(FIELD_SSN), nullValue());
                assertThat("salary should not be visible with FLS", source.get(FIELD_SALARY), nullValue());
                assertThat("name should be visible with FLS", source.get(FIELD_NAME), not(nullValue()));
                assertThat("department should be visible with FLS", source.get(FIELD_DEPARTMENT), not(nullValue()));
            }
        }
    }
}
