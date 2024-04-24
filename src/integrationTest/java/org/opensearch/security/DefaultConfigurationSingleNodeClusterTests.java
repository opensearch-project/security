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
import org.junit.ClassRule;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DefaultConfigurationSingleNodeClusterTests extends AbstractDefaultConfigurationTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .nodeSettings(
            Map.of(
                "plugins.security.allow_default_init_securityindex",
                true,
                "plugins.security.restapi.roles_enabled",
                List.of("user_admin__all_access")
            )
        )
        .defaultConfigurationInitDirectory(configurationFolder.toString())
        .loadConfigurationIntoIndex(false)
        .build();

    public DefaultConfigurationSingleNodeClusterTests() {
        super(cluster);
    }

}
