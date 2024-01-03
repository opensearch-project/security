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

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.commons.io.FileUtils;
import org.awaitility.Awaitility;
import org.junit.AfterClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.client.Client;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.ContextHeaderDecoratorClient;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.configuration.ConfigurationRepository.DEFAULT_CONFIG_VERSION;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_DELAY_INITIALIZATION_SECONDS;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SecurityConfigurationBootstrapTests {

    private final static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();

    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .loadConfigurationIntoIndex(false)
        .defaultConfigurationInitDirectory(configurationFolder.toString())
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX,
                true,
                SECURITY_UNSUPPORTED_DELAY_INITIALIZATION_SECONDS,
                5
            )
        )
        .build();

    @AfterClass
    public static void cleanConfigurationDirectory() throws IOException {
        FileUtils.deleteDirectory(configurationFolder.toFile());
    }

    @Test
    public void shouldStillLoadSecurityConfigDuringBootstrapAndActiveConfigUpdateRequests() throws Exception {
        cluster.getInternalNodeClient()
            .admin()
            .cluster()
            .health(new ClusterHealthRequest(OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX).waitForGreenStatus())
            .actionGet();
        Client internalNodeClient = new ContextHeaderDecoratorClient(
            cluster.getInternalNodeClient(),
            Map.of(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true")
        );
        String cd = System.getProperty("security.default_init.dir") + "/";
        ConfigHelper.uploadFile(
            internalNodeClient,
            cd + "action_groups.yml",
            OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX,
            CType.ACTIONGROUPS,
            DEFAULT_CONFIG_VERSION
        );
        ConfigHelper.uploadFile(
            internalNodeClient,
            cd + "config.yml",
            OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX,
            CType.CONFIG,
            DEFAULT_CONFIG_VERSION
        );
        ConfigHelper.uploadFile(
            internalNodeClient,
            cd + "roles.yml",
            OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX,
            CType.ROLES,
            DEFAULT_CONFIG_VERSION
        );
        ConfigHelper.uploadFile(
            internalNodeClient,
            cd + "tenants.yml",
            OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX,
            CType.TENANTS,
            DEFAULT_CONFIG_VERSION
        );
        long t = System.currentTimeMillis();
        long end = t + 10000;
        while (System.currentTimeMillis() < end) {
            cluster.triggerConfigurationReloadForCTypes(
                internalNodeClient,
                List.of(CType.ACTIONGROUPS, CType.CONFIG, CType.ROLES, CType.TENANTS),
                true
            );
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                break;
            }
        }
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Awaitility.await().alias("Load default configuration").until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
        }
    }
}
