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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class LegacyConfigV6AutoConversionTest {
    static final TestSecurityConfig LEGACY_CONFIG = new TestSecurityConfig()//
        .rawConfigurationDocumentYaml("config", """
            opendistro_security:
              dynamic:
                authc:
                  basic_internal_auth_domain:
                    http_enabled: true
                    order: 4
                    http_authenticator:
                      type: basic
                      challenge: true
                    authentication_backend:
                      type: intern
                      """)//
        .rawConfigurationDocumentYaml("internalusers", """
            admin:
              readonly: true
              hash: $2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG
              roles:
                - admin
              attributes:
                attribute1: value1
            """)//
        .rawConfigurationDocumentYaml("roles", """
            all_access:
              readonly: true
              cluster:
                - UNLIMITED
              indices:
                '*':
                  '*':
                    - UNLIMITED
              tenants:
                admin_tenant: RW
                """)//
        .rawConfigurationDocumentYaml("rolesmapping", """
            all_access:
              readonly: true
              backendroles:
                - admin
            """);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .config(LEGACY_CONFIG)
        .build();

    @Test
    public void checkAuthc() {
        try (TestRestClient client = cluster.getRestClient("admin", "admin")) {
            TestRestClient.HttpResponse response = client.get("_opendistro/_security/authinfo");
            System.out.println(response.getBody());
        }
    }
}
