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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.index.query.QueryBuilders;
import org.opensearch.indices.TermsLookup;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.matcher.RestMatchers.isInternalServerError;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ParentChildRelationTests {
    public static final String INDEX_NAME = "dlstest";
    public static final String TERM_LOOKUP_INDEX_NAME = "term_lookup_index";
    public static final String TERMS_DOC_ID = "terms_2_2000";
    public static final String TERM_PATH = "terms_to_search";

    private static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);
    private static final User DLS_TEST_USER = new User("dls_test_user").roles(
        new Role("dls_test_role") //
            .clusterPermissions("*") //
            .indexPermissions("read") //
            .dls(QueryBuilders.termQuery("dls", "2")) //
            .on(INDEX_NAME)
    );
    private static final User DLS_TLQ_TEST_USER = new User("dls_tlq_test_user").roles(
        new Role("dls_tlq_test_role").clusterPermissions("*") //
            .indexPermissions("read") //
            .dls(QueryBuilders.termsLookupQuery("dsl", new TermsLookup(TERM_LOOKUP_INDEX_NAME, TERMS_DOC_ID, TERM_PATH))) //
            .on(INDEX_NAME)
    );

    public static final int BASIC_AUTH_DOMAIN_ORDER = 0;
    public final static AuthcDomain AUTHC_HTTPBASIC_INTERNAL = new AuthcDomain("basic", BASIC_AUTH_DOMAIN_ORDER) //
        .httpAuthenticatorWithChallenge("basic") //
        .backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE) //
        .anonymousAuth(false) //
        .authc(AUTHC_HTTPBASIC_INTERNAL) //
        .users(ADMIN_USER, DLS_TEST_USER, DLS_TLQ_TEST_USER) //
        .build();

    @BeforeClass
    public static void beforeClass() {
        Map<String, Object> indexMapping = Map.of(
            "properties",
            Map.of(
                "dls",
                Map.of("type", "keyword"),
                "entityStatements",
                Map.of("type", "join", "relations", Map.of("entity", "statements"))
            )
        );
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            // first create an index
            HttpResponse response = client.put(INDEX_NAME);
            assertThat(response, isOk());
            // this will fail if the index does not exist
            IndexOperationsHelper.createMapping(cluster, INDEX_NAME, indexMapping);
        }
        try (Client client = cluster.getInternalNodeClient()) {
            Map<String, Object> document = Map.of("dls", "1", "entityStatements", "entity");
            client.prepareIndex(INDEX_NAME).setId("1").setRefreshPolicy(IMMEDIATE).setSource(document).get();
            document = Map.of("dls", "2", "entityStatements", "entity");
            client.prepareIndex(INDEX_NAME).setId("2").setRefreshPolicy(IMMEDIATE).setSource(document).get();
            document = Map.of("dls", "1", "entityStatements", Map.of("name", "statements", "parent", "1"));
            client.prepareIndex(INDEX_NAME).setId("3").setRouting("1").setRefreshPolicy(IMMEDIATE).setSource(document).get();
            document = Map.of("dls", "2", "entityStatements", Map.of("name", "statements", "parent", "1"));
            client.prepareIndex(INDEX_NAME).setId("4").setRouting("1").setRefreshPolicy(IMMEDIATE).setSource(document).get();
            document = Map.of("dls", "2", "entityStatements", Map.of("name", "statements", "parent", "2"));
            client.prepareIndex(INDEX_NAME).setId("5").setRouting("1").setRefreshPolicy(IMMEDIATE).setSource(document).get();
            document = Map.of("dls", "3", "entityStatements", Map.of("name", "statements", "parent", "2"));
            client.prepareIndex(INDEX_NAME).setId("6").setRouting("1").setRefreshPolicy(IMMEDIATE).setSource(document).get();

            // create a term lookup index
            document = Map.of(TERM_PATH, List.of("2", "2000"));
            client.prepareIndex(TERM_LOOKUP_INDEX_NAME).setId(TERMS_DOC_ID).setRefreshPolicy(IMMEDIATE).setSource(document).get();
        }
    }

    @Test
    public void dlsUserSearchAll() {
        try (TestRestClient client = cluster.getRestClient(DLS_TEST_USER)) {
            HttpResponse response = client.get(INDEX_NAME + "/_search?pretty");
            assertThat(response, isOk());
            JsonNode hits = response.bodyAsJsonNode().get("hits").get("hits");
            assertThat(hits.size(), equalTo(3));
            for (JsonNode hit : hits) {
                String dlsValue = hit.get("_source").get("dls").asText();
                assertThat(dlsValue, equalTo("2"));
            }
        }
    }

    @Test
    public void hasParentWithDlsDisallowedParentQuery() {
        try (TestRestClient client = cluster.getRestClient(DLS_TEST_USER)) {
            HttpResponse response = client.postJson(INDEX_NAME + "/_search?pretty", """
                {
                    "query": {
                        "has_parent": {
                            "parent_type": "entity",
                            "query": {
                                "match": {
                                    "dls": "1"
                                }
                            }
                        }
                    }
                }
                """);
            assertThat(response, isOk());
            JsonNode hits = response.bodyAsJsonNode().get("hits").get("hits");
            assertThat(hits.size(), equalTo(0));
        }
    }

    @Test
    public void hasParentWithDlsAllowedParentQuery() {
        try (TestRestClient client = cluster.getRestClient(DLS_TEST_USER)) {
            HttpResponse response = client.postJson(INDEX_NAME + "/_search?pretty", """
                {
                    "query": {
                        "has_parent": {
                            "parent_type": "entity",
                            "query": {
                                "match": {
                                    "dls": "2"
                                }
                            }
                        }
                    }
                }
                """);
            assertThat(response, isOk());
            JsonNode hits = response.bodyAsJsonNode().get("hits").get("hits");
            assertThat(hits.size(), equalTo(1));
            String documentId = response.bodyAsJsonNode().get("hits").get("hits").get(0).get("_id").asText();
            assertThat(documentId, equalTo("5"));
        }
    }

    @Test
    public void hasChildWithDlsDisallowedChild() {
        try (TestRestClient client = cluster.getRestClient(DLS_TEST_USER)) {
            HttpResponse response = client.postJson(INDEX_NAME + "/_search?pretty", """
                {
                    "query": {
                        "has_child": {
                            "type": "statements",
                            "query": {
                                "match": {
                                    "dls": "3"
                                }
                            }
                        }
                    }
                }
                """);
            assertThat(response, isOk());
            JsonNode hits = response.bodyAsJsonNode().get("hits").get("hits");
            assertThat(hits.size(), equalTo(0));
        }
    }

    @Test
    public void hasChildWithDlsAllowedChild() {
        try (TestRestClient client = cluster.getRestClient(DLS_TEST_USER)) {
            HttpResponse response = client.postJson(INDEX_NAME + "/_search?pretty", """
                {
                    "query": {
                        "has_child": {
                            "type": "statements",
                            "query": {
                                "match": {
                                    "dls": "2"
                                }
                            }
                        }
                    }
                }
                """);
            assertThat(response, isOk());
            JsonNode hits = response.bodyAsJsonNode().get("hits").get("hits");
            assertThat(hits.size(), equalTo(1));
            String documentId = response.bodyAsJsonNode().get("hits").get("hits").get(0).get("_id").asText();
            assertThat(documentId, equalTo("2"));
        }
    }

    @Test
    public void hasParentWithTlqDls() {
        try (TestRestClient client = cluster.getRestClient(DLS_TLQ_TEST_USER)) {
            HttpResponse response = client.postJson(INDEX_NAME + "/_search?pretty", """
                {
                    "query": {
                        "has_parent": {
                            "parent_type": "entity",
                            "query": {
                                "match": {
                                    "dls": "1"
                                }
                            }
                        }
                    }
                }
                """);
            assertThat(response, isInternalServerError("/error/reason", "Unable to handle filter level DLS for parent or child queries"));
        }
    }
}
