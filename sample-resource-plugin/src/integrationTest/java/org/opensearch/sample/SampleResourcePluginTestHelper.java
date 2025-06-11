/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample;

import org.opensearch.test.framework.TestSecurityConfig;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
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

    protected static final String RESOURCE_SHARING_MIGRATION_ENDPOINT = "_plugins/_security/api/resources/migrate";

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

    protected static String migrationPayload_valid() {
        return """
            {
            "source_index": "%s",
            "username_path": "%s",
            "backend_roles_path": "%s"
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/name", "user/backend_roles");
    }

    protected static String migrationPayload_valid_withSpecifiedAccessLevel() {
        return """
            {
            "source_index": "%s",
            "username_path": "%s",
            "backend_roles_path": "%s",
            "default_access_level": "%s"
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/name", "user/backend_roles", "read_only");
    }

    protected static String migrationPayload_missingSourceIndex() {
        return """
            {
            "username_path": "%s",
            "backend_roles_path": "%s"
            }
            """.formatted("user/name", "user/backend_roles");
    }

    protected static String migrationPayload_missingUserName() {
        return """
            {
            "source_index": "%s",
            "backend_roles_path": "%s"
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/backend_roles");
    }

    protected static String migrationPayload_missingBackendRoles() {
        return """
            {
            "source_index": "%s",
            "username_path": "%s"
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/name");
    }
}
