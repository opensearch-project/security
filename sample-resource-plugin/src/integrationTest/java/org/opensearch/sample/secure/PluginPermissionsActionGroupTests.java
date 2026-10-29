/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.sample.secure;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_PREFIX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * Verifies that action-group names in {@code plugin-additional-permissions.yml} grant the actions they stand for.
 * The sample plugin grants {@code read} on {@code test-index*} and {@code cluster_manage_pipelines}; no literal action
 * in its file covers search or get pipeline.
 * <p>
 * Each subclass starts one cluster. The static security configuration stays loaded in the JVM after the first node
 * starts, so a second node in the same JVM would not show the startup order of a production node. The build runs each
 * test class in its own JVM.
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public abstract class PluginPermissionsActionGroupTests {

    private static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0).httpAuthenticatorWithChallenge("basic").backend("internal");
    private static final String GRANTED_INDEX = "test-index-action-group";
    private static final String OTHER_INDEX = "other-index-action-group";

    private final LocalCluster cluster;
    private final String privilegesEvaluationType;

    /**
     * Creates the tests for a cluster.
     *
     * @param cluster the cluster under test
     * @param privilegesEvaluationType the type the cluster starts with, {@code legacy} or {@code v4}
     */
    protected PluginPermissionsActionGroupTests(LocalCluster cluster, String privilegesEvaluationType) {
        this.cluster = cluster;
        this.privilegesEvaluationType = privilegesEvaluationType;
    }

    /**
     * Returns a builder for a single node cluster with the sample plugin installed.
     *
     * @param privilegesEvaluationType {@code legacy} or {@code v4}
     * @return the cluster builder
     */
    protected static LocalCluster.Builder clusterBuilder(String privilegesEvaluationType) {
        return new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .anonymousAuth(false)
            .authc(AUTHC_DOMAIN)
            .users(USER_ADMIN)
            .privilegesEvaluationType(privilegesEvaluationType)
            .plugin(
                new PluginInfo(
                    SampleResourcePlugin.class.getName(),
                    "classpath plugin",
                    "NA",
                    Version.CURRENT,
                    "1.8",
                    SampleResourcePlugin.class.getName(),
                    null,
                    List.of(OpenSearchSecurityPlugin.class.getName()),
                    false
                )
            )
            .nodeSettings(
                Map.of(SECURITY_SYSTEM_INDICES_ENABLED_KEY, true, SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
            );
    }

    /**
     * Indexes one document into the granted index and one into the other index.
     */
    @Before
    public void indexDocuments() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            for (String index : List.of(GRANTED_INDEX, OTHER_INDEX)) {
                HttpResponse response = client.putJson(index + "/_doc/1?refresh=true", """
                    {"field": "value"}
                    """);
                assertThat(response.getBody(), response.getStatusCode(), is(oneOf(200, 201)));
            }
        }
    }

    /**
     * No literal action in the permissions file grants search, so only the {@code read} group can, and only on the
     * index patterns of its entry.
     */
    @Test
    public void testReadActionGroupGrantsSearchOnItsIndexPattern() {
        assertPluginSearchFindsDocument();

        HttpResponse response = runAction("indices:data/read/search", OTHER_INDEX);

        assertThat(response, isForbidden("/error/root_cause/0/reason", "no permissions for [indices:data/read/search]"));
    }

    /**
     * No literal action in the permissions file grants get pipeline, so only the {@code cluster_manage_pipelines}
     * group can.
     */
    @Test
    public void testClusterActionGroupGrantsGetPipeline() {
        HttpResponse response = runAction("cluster:admin/ingest/pipeline/get", null);

        assertThat(response, isOk());
        assertThat(response.getTextFromJsonBody("/message"), equalTo("number_of_pipelines: 0"));
    }

    /**
     * An update of the dynamic action groups keeps the plugin privileges.
     */
    @Test
    public void testActionGroupsUpdateKeepsPluginPrivileges() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse response = client.putJson("_plugins/_security/api/actiongroups/custom_group", """
                {"allowed_actions": ["indices:data/read/get"]}
                """);
            assertThat(response.getBody(), response.getStatusCode(), is(oneOf(200, 201)));
            try {
                assertPluginSearchFindsDocument();
            } finally {
                client.delete("_plugins/_security/api/actiongroups/custom_group");
            }
        }
    }

    /**
     * A change of the privileges evaluation type builds a new evaluator, which resolves the plugin privileges again.
     */
    @Test
    public void testActionGroupsResolveAfterEvaluatorTypeChange() {
        String otherType = "v4".equals(privilegesEvaluationType) ? "legacy" : "v4";
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            setPrivilegesEvaluationType(client, otherType);
            try {
                assertPluginSearchFindsDocument();
            } finally {
                setPrivilegesEvaluationType(client, privilegesEvaluationType);
            }
        }
    }

    private static void setPrivilegesEvaluationType(TestRestClient client, String type) {
        HttpResponse response = client.patch("_plugins/_security/api/securityconfig", """
            [{"op": "add", "path": "/config/dynamic/privileges_evaluation_type", "value": "%s"}]
            """.formatted(type));
        assertThat(response, isOk());
    }

    private void assertPluginSearchFindsDocument() {
        HttpResponse response = runAction("indices:data/read/search", GRANTED_INDEX);

        assertThat(response, isOk());
        assertThat(response.getTextFromJsonBody("/message"), equalTo("number_of_hits: 1"));
    }

    private HttpResponse runAction(String action, String index) {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            return client.postJson(SAMPLE_RESOURCE_PLUGIN_PREFIX + "/run_action", """
                {"action": "%s", "index": %s}
                """.formatted(action, index == null ? "null" : "\"" + index + "\""));
        }
    }
}
