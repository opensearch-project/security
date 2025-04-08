/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.nonsystemindex;

import java.util.Map;

import org.junit.ClassRule;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.sample.nonsystemindex.plugin.ResourceNonSystemIndexPlugin;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.sample.utils.Constants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing enabled but the plugin does not declare a system index and system index protection is disabled
 */
public class ResourceNonSystemIndexSIDisabledTests extends AbstractResourcePluginNonSystemIndexTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(ResourceNonSystemIndexPlugin.class, PainlessModulePlugin.class)
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, SHARED_WITH_USER)
        .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, true))
        .build();

    @Override
    protected LocalCluster getLocalCluster() {
        return cluster;
    }
}
