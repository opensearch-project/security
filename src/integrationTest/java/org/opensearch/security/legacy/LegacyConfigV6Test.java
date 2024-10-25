/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.legacy;

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class LegacyConfigV6Test {
    static final TestSecurityConfig LEGACY_CONFIG = new TestSecurityConfig()//
        .rawConfigurationDocumentYaml(
            "config",
            "opendistro_security:\n"
                + "  dynamic:\n"
                + "    authc:\n"
                + "      basic_internal_auth_domain:\n"
                + "        http_enabled: true\n"
                + "        order: 4\n"
                + "        http_authenticator:\n"
                + "          type: basic\n"
                + "          challenge: true\n"
                + "        authentication_backend:\n"
                + "          type: intern\n"
        )
        .rawConfigurationDocumentYaml(
            "internalusers",
            "admin:\n"
                + "  readonly: true\n"
                + "  hash: $2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG\n"
                + "  roles:\n"
                + "  - admin\n"
                + "  attributes:\n"
                + "    attribute1: value1\n"
        )
        .rawConfigurationDocumentYaml(
            "roles",
            "all_access_role:\n"
                + "  readonly: true\n"
                + "  cluster:\n"
                + "  - UNLIMITED\n"
                + "  indices:\n"
                + "    '*':\n"
                + "      '*':\n"
                + "      - UNLIMITED\n"
                + "  tenants:\n"
                + "    admin_tenant: RW\n"
        )
        .rawConfigurationDocumentYaml("rolesmapping", "all_access_role:\n" + "  readonly: true\n" + "  backendroles:\n" + "  - admin")//
        .rawConfigurationDocumentYaml("actiongroups", "dummy:\n" + "  permissions: []");

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .config(LEGACY_CONFIG)
        .nodeSettings(Map.of("plugins.security.restapi.roles_enabled.0", "all_access_role"))
        .build();

    @Test
    public void authc() {
        try (TestRestClient client = cluster.getRestClient("admin", "admin")) {
            TestRestClient.HttpResponse response = client.get("_opendistro/_security/authinfo");
            Assert.assertEquals(response.getBody(), 200, response.getStatusCode());
            Assert.assertEquals(response.getBody(), true, response.getBooleanFromJsonBody("/tenants/admin"));
        }
    }

    @Test
    public void configRestApiReturnsV6Config() {
        try (TestRestClient client = cluster.getRestClient("admin", "admin")) {
            TestRestClient.HttpResponse response = client.get("_opendistro/_security/api/roles/all_access_role");
            Assert.assertEquals(response.getBody(), 200, response.getStatusCode());
            Assert.assertEquals(
                "Expected v6 format",
                "{\"all_access_role\":{\"readonly\":true,\"hidden\":false,\"cluster\":[\"UNLIMITED\"],\"tenants\":{\"admin_tenant\":\"RW\"},\"indices\":{\"*\":{\"*\":[\"UNLIMITED\"]}}}}",
                response.getBody()
            );
        }
    }

}
