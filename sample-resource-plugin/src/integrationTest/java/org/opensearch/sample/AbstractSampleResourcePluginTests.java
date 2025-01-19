package org.opensearch.sample;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.runner.RunWith;

import org.opensearch.security.spi.resources.ResourceAccessScope;
import org.opensearch.test.framework.TestSecurityConfig;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

/**
 * These tests run with security enabled
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AbstractSampleResourcePluginTests {

    final static TestSecurityConfig.User SHARED_WITH_USER = new TestSecurityConfig.User("resource_sharing_test_user").roles(
        new TestSecurityConfig.Role("shared_role").indexPermissions("*").on("*").clusterPermissions("*")
    );

    static final String SAMPLE_RESOURCE_CREATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/create";
    static final String SAMPLE_RESOURCE_UPDATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/update";
    static final String SAMPLE_RESOURCE_DELETE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/delete";
    static final String SECURITY_RESOURCE_LIST_ENDPOINT = PLUGINS_PREFIX + "/resources/list";
    static final String SECURITY_RESOURCE_SHARE_ENDPOINT = PLUGINS_PREFIX + "/resources/share";
    static final String SECURITY_RESOURCE_VERIFY_ENDPOINT = PLUGINS_PREFIX + "/resources/verify_access";
    static final String SECURITY_RESOURCE_REVOKE_ENDPOINT = PLUGINS_PREFIX + "/resources/revoke";

    static String shareWithPayload(String resourceId) {
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
            + SHARED_WITH_USER.getName()
            + "\"]"
            + "}"
            + "}"
            + "}";
    }

    static String revokeAccessPayload(String resourceId) {
        return "{"
            + "\"resource_id\": \""
            + resourceId
            + "\","
            + "\"resource_index\": \""
            + RESOURCE_INDEX_NAME
            + "\","
            + "\"entities\": {"
            + "\"users\": [\""
            + SHARED_WITH_USER.getName()
            + "\"]"
            + "},"
            + "\"scopes\": [\""
            + ResourceAccessScope.PUBLIC
            + "\"]"
            + "}";
    }
}
