/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.security;

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
import org.opensearch.transport.client.Client;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class TermsLookupFieldRestrictionsTest {
    private static final User FLS_USER = new User("fls_user").roles(
        new Role("fls").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").fls("name").on("lookup"),
        lookupRole()
    );
    private static final User MASKED_USER = new User("masked_user").roles(
        new Role("masked").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .maskedFields("secret::/.+/::hidden")
            .on("lookup"),
        lookupRole()
    );

    private static Role lookupRole() {
        return new Role("lookup_dls").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(QueryBuilders.termsLookupQuery("department", new TermsLookup("lookup", "1", "secret")))
            .on("documents");
    }

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(FLS_USER, MASKED_USER)
        .build();

    @BeforeClass
    public static void indexDocuments() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex("lookup")
                .setId("1")
                .setSource(Map.of("name", "lookup", "secret", "engineering"))
                .setRefreshPolicy(IMMEDIATE)
                .get();
            client.prepareIndex("documents")
                .setId("allowed")
                .setSource(Map.of("department", "engineering"))
                .setRefreshPolicy(IMMEDIATE)
                .get();
            client.prepareIndex("documents").setId("denied").setSource(Map.of("department", "marketing")).setRefreshPolicy(IMMEDIATE).get();
        }
    }

    @Test
    public void flsSurvivesLookupInMultiIndexSearch() {
        assertFieldRestrictions(FLS_USER);
    }

    @Test
    public void fieldMaskingSurvivesLookupInMultiIndexSearch() {
        assertFieldRestrictions(MASKED_USER);
    }

    private void assertFieldRestrictions(User user) {
        try (TestRestClient client = cluster.getRestClient(user)) {
            var response = client.get("documents,lookup/_search");
            assertThat(response, isOk());
            JsonNode body = response.bodyAsJsonNode();
            assertThat(body.at("/_shards/failed").asInt(), equalTo(0));
            assertThat(body.at("/hits/total/value").asInt(), equalTo(2));
            int lookupHits = 0;
            int documentHits = 0;
            for (JsonNode hit : body.at("/hits/hits")) {
                if ("lookup".equals(hit.get("_index").asText())) {
                    lookupHits++;
                    assertThat(hit.at("/_source/name").asText(), equalTo("lookup"));
                    if (user == FLS_USER) {
                        assertThat(hit.get("_source").get("secret"), nullValue());
                    } else {
                        assertThat(hit.at("/_source/secret").asText(), equalTo("hidden"));
                    }
                } else {
                    documentHits++;
                    assertThat(hit.get("_id").asText(), equalTo("allowed"));
                }
            }
            assertThat(lookupHits, equalTo(1));
            assertThat(documentHits, equalTo(1));
        }
    }
}
