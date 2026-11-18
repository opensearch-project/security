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
package org.opensearch.security;

import java.util.Map;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.transport.client.Client;

import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
 * Tests do_not_fail_on_forbidden together with do_not_fail_on_forbidden_empty for a user without privileges on any existing index.
 */
public class DoNotFailOnForbiddenEmptyResultsTests {

    private static final User NO_MATCHING_INDEX_USER = new User("no_matching_index_user").roles(
        new Role("no-matching-index-role").indexPermissions("indices:admin/get").on("no_such_index*")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(NO_MATCHING_INDEX_USER)
        .anonymousAuth(false)
        .doNotFailOnForbidden(true)
        .nodeSettings(Map.of(SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true))
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index("other_index").id("1").source("field", "value")).actionGet();
        }
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.patch(
                "_plugins/_security/api/securityconfig",
                "[{\"op\":\"add\",\"path\":\"/config/dynamic/do_not_fail_on_forbidden_empty\",\"value\":true}]"
            ).assertStatusCode(SC_OK);
        }
    }

    @Test
    public void shouldGetIndex_emptyResult() {
        try (TestRestClient client = cluster.getRestClient(NO_MATCHING_INDEX_USER)) {
            HttpResponse response = client.get("_all");

            response.assertStatusCode(SC_OK);
            assertThat(response.getBody(), response.bodyAsMap(), anEmptyMap());
        }
    }
}
