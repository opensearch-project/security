/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample;

import org.opensearch.test.framework.TestSecurityConfig;

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
            "cluster:admin/sample-resource-plugin/get",
            "cluster:admin/sample-resource-plugin/create",
            "cluster:admin/sample-resource-plugin/share",
            "cluster:admin/sample-resource-plugin/revoke"
        )
    );

    protected static final TestSecurityConfig.ActionGroup sampleReadOnlyAG = new TestSecurityConfig.ActionGroup(
        "sample_plugin_index_read_access",
        TestSecurityConfig.ActionGroup.Type.INDEX,
        "indices:data/read*",
        "cluster:admin/sample-resource-plugin/get"
    );
    protected static final TestSecurityConfig.ActionGroup sampleAllAG = new TestSecurityConfig.ActionGroup(
        "sample_plugin_index_all_access",
        TestSecurityConfig.ActionGroup.Type.INDEX,
        "indices:*",
        "cluster:admin/sample-resource-plugin/*"
    );

    protected static final String SAMPLE_RESOURCE_CREATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/create";
    protected static final String SAMPLE_RESOURCE_GET_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/get";
    protected static final String SAMPLE_RESOURCE_UPDATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/update";
    protected static final String SAMPLE_RESOURCE_DELETE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/delete";
    protected static final String SAMPLE_RESOURCE_SHARE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/share";
    protected static final String SAMPLE_RESOURCE_REVOKE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/revoke";

    protected static String shareWithPayload(String user, String accessLevel) {
        return """
            {
              "share_with": {
                "%s" : {
                    "users": ["%s"]
                }
              }
            }
            """.formatted(accessLevel, user);
    }

    protected static String revokeAccessPayload(String user, String accessLevel) {
        return """
            {
              "entities_to_revoke": {
                "%s" : {
                    "users": ["%s"]
                }
              }
            }
            """.formatted(accessLevel, user);

    }
}
