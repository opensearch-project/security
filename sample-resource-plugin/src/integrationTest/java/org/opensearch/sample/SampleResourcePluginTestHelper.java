/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.resources.ResourceAccessControlClient;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_PREFIX;

/**
 * Abstract class for sample resource plugin tests. Provides common constants and utility methods for testing. This class is not intended to be
 * instantiated directly. It is extended by {@link SampleResourcePluginLimitedPermissionsTests}, {@link SampleResourcePluginSystemIndexDisabledTests}, {@link SampleResourcePluginTests}, {@link SampleResourcePluginFeatureDisabledTests}
 */
public abstract class SampleResourcePluginTestHelper {

    protected final static TestSecurityConfig.User SHARED_WITH_USER = new TestSecurityConfig.User("resource_sharing_test_user").roles(
        new TestSecurityConfig.Role("shared_role").indexPermissions("*").on("*").clusterPermissions("*")
    );

    // No update permission
    protected final static TestSecurityConfig.User SHARED_WITH_USER_LIMITED_PERMISSIONS = new TestSecurityConfig.User(
        "resource_sharing_test_user_limited_perms"
    ).roles(
        new TestSecurityConfig.Role("shared_role_limited_perms").clusterPermissions(
            "cluster:admin/security/resource_access/*",
            "cluster:admin/sample-resource-plugin/get",
            "cluster:admin/sample-resource-plugin/create",
            "cluster:admin/sample-resource-plugin/share",
            "cluster:admin/sample-resource-plugin/revoke"
        )
    );

    protected static final String SAMPLE_RESOURCE_CREATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/create";
    protected static final String SAMPLE_RESOURCE_GET_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/get";
    protected static final String SAMPLE_RESOURCE_UPDATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/update";
    protected static final String SAMPLE_RESOURCE_DELETE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/delete";
    protected static final String SAMPLE_RESOURCE_SHARE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/share";
    protected static final String SAMPLE_RESOURCE_REVOKE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/revoke";

    protected static ResourceSharingClient createResourceAccessControlClient(LocalCluster cluster) {
        ResourceAccessHandler rAH = cluster.nodes().getFirst().getInjectable(ResourceAccessHandler.class);
        Settings settings = cluster.node().settings();
        return new ResourceAccessControlClient(rAH, settings);
    }

    protected static String shareWithPayload(String user) {
        return """
            {
              "share_with": {
                "users": ["%s"]
              }
            }
            """.formatted(user);
    }

    protected static String revokeAccessPayload(String user) {
        return """
            {
              "entities_to_revoke": {
                "users": ["%s"]
              }
            }
            """.formatted(user);

    }
}
