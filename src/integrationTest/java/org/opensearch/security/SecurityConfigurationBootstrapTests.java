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
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.client.Client;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.ContextHeaderDecoratorClient;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SecurityConfigurationBootstrapTests {

    private final static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();

    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .loadConfigurationIntoIndex(false)
        .defaultConfigurationInitDirectory(configurationFolder.toString())
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX,
                true
            )
        )
        .build();

    @BeforeClass
    public static void runConfigUpdateRequestsInBgThread() {

        Client client = new ContextHeaderDecoratorClient(
            cluster.getInternalNodeClient(),
            Map.of(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true")
        );
        Runnable r = new Runnable() {
            public void run() {
                long t = System.currentTimeMillis();
                long end = t + 10000;
                while (System.currentTimeMillis() < end) {
                    cluster.triggerConfigurationReloadForSingleCType(client, CType.CONFIG, true);
                    try {
                        Thread.sleep(50);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            }
        };

        new Thread(r).start();
    }

    @AfterClass
    public static void cleanConfigurationDirectory() throws IOException {
        FileUtils.deleteDirectory(configurationFolder.toFile());
    }

    @Test
    public void shouldStillLoadSecurityConfigDuringBootstrapAndActiveConfigUpdateRequests() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Awaitility.await().alias("Load default configuration").until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
        }
    }
}
