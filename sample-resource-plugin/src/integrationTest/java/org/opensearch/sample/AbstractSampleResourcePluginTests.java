/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample;

import org.opensearch.security.spi.resources.ResourceAccessScope;
import org.opensearch.test.framework.TestSecurityConfig;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_RESOURCE_ROUTE_PREFIX;

/**
 * Abstract class for sample resource plugin tests. Provides common constants and utility methods for testing. This class is not intended to be
 * instantiated directly. It is extended by {@link AbstractSampleResourcePluginFeatureEnabledTests}, {@link SampleResourcePluginFeatureDisabledTests}, {@link org.opensearch.sample.nonsystemindex.AbstractResourcePluginNonSystemIndexTests}
 */
public abstract class AbstractSampleResourcePluginTests {

    protected final static TestSecurityConfig.User SHARED_WITH_USER = new TestSecurityConfig.User("resource_sharing_test_user").roles(
        new TestSecurityConfig.Role("shared_role").indexPermissions("*").on("*").clusterPermissions("*")
    );

    // No update permission
    protected final static TestSecurityConfig.User SHARED_WITH_USER_LIMITED_PERMISSIONS = new TestSecurityConfig.User(
        "resource_sharing_test_user_limited_perms"
    ).roles(
        new TestSecurityConfig.Role("shared_role_limited_perms").clusterPermissions(
            "cluster:admin/security/resource_access",
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
    private static final String PLUGIN_RESOURCE_ROUTE_PREFIX_NO_LEADING_SLASH = PLUGIN_RESOURCE_ROUTE_PREFIX.replaceFirst("/", "");
    protected static final String SECURITY_RESOURCE_LIST_ENDPOINT = PLUGIN_RESOURCE_ROUTE_PREFIX_NO_LEADING_SLASH + "/list";
    protected static final String SECURITY_RESOURCE_SHARE_ENDPOINT = PLUGIN_RESOURCE_ROUTE_PREFIX_NO_LEADING_SLASH + "/share";
    protected static final String SECURITY_RESOURCE_VERIFY_ENDPOINT = PLUGIN_RESOURCE_ROUTE_PREFIX_NO_LEADING_SLASH + "/verify_access";
    protected static final String SECURITY_RESOURCE_REVOKE_ENDPOINT = PLUGIN_RESOURCE_ROUTE_PREFIX_NO_LEADING_SLASH + "/revoke";

    protected static String shareWithPayloadSecurityApi(String resourceId, String user) {
        return "{"
            + "\"resource_id\":\""
            + resourceId
            + "\","
            + "\"resource_index\":\""
            + RESOURCE_INDEX_NAME
            + "\","
            + "\"share_with\":{"
            + "\""
            + SampleResourceScope.PUBLIC.value()
            + "\":{"
            + "\"users\": [\""
            + user
            + "\"]"
            + "}"
            + "}"
            + "}";
    }

    protected static String shareWithPayload(String user) {
        return "{"
            + "\"share_with\":{"
            + "\""
            + SampleResourceScope.PUBLIC.value()
            + "\":{"
            + "\"users\": [\""
            + user
            + "\"]"
            + "}"
            + "}"
            + "}";
    }

    protected static String revokeAccessPayloadSecurityApi(String resourceId, String user) {
        return "{"
            + "\"resource_id\": \""
            + resourceId
            + "\","
            + "\"resource_index\": \""
            + RESOURCE_INDEX_NAME
            + "\","
            + "\"entities_to_revoke\": {"
            + "\"users\": [\""
            + user
            + "\"]"
            + "},"
            + "\"scopes\": [\""
            + ResourceAccessScope.PUBLIC
            + "\"]"
            + "}";
    }

    protected static String revokeAccessPayload(String user) {
        return "{"
            + "\"entities_to_revoke\": {"
            + "\"users\": [\""
            + user
            + "\"]"
            + "},"
            + "\"scopes\": [\""
            + ResourceAccessScope.PUBLIC
            + "\"]"
            + "}";
    }

    protected static String verifyAccessPayload(String resourceId) {
        return "{"
            + "\"resource_id\":\""
            + resourceId
            + "\","
            + "\"resource_index\":\""
            + RESOURCE_INDEX_NAME
            + "\","
            + "\"scopes\":[\""
            + ResourceAccessScope.PUBLIC
            + "\"]"
            + "}";
    }
}
