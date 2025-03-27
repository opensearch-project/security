package org.opensearch.security.configuration;

import org.junit.Assert;
import org.junit.Test;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SettingsPermissionValveTests extends SingleClusterTest {
    private static final String STRONG_PASSWORD = "p@sSVVVAA##@worD!";
    private static final String ADMIN_PASSWORD = "nagilum";

    @Test
    public void testClusterSettingsPermissions() throws Exception {
        setupTestUsers();
        
        // Test admin user can update any settings
        RestHelper.HttpResponse response = nonSslRestHelper().executePutRequest(
            "_cluster/settings",
            "{\"persistent\":{\"cluster.routing.allocation.enable\":\"none\"}}",
            encodeBasicHeader("admin", ADMIN_PASSWORD)
        );
        log.info("Response: {}", response.getBody());
        Assert.assertEquals(200, response.getStatusCode());

        // Test user with specific cluster settings permission
        response = nonSslRestHelper().executePutRequest(
            "_cluster/settings",
            "{\"persistent\":{\"cluster.routing.allocation.enable\":\"none\"}}",
            encodeBasicHeader("cluster_settings_user", STRONG_PASSWORD)
        );
        log.info("Response: {}", response.getBody());
        Assert.assertEquals(200, response.getStatusCode());

        // Test user without cluster settings permission
        response = nonSslRestHelper().executePutRequest(
            "_cluster/settings",
            "{\"persistent\":{\"cluster.routing.allocation.enable\":\"none\"}}",
            encodeBasicHeader("no_settings_user", STRONG_PASSWORD)
        );
        log.info("Response: {}", response.getBody());
        Assert.assertEquals(403, response.getStatusCode());
    }

    @Test
    public void testIndexSettingsPermissions() throws Exception {
        setupTestUsers();
        createTestIndex();

        // Test admin user can update any index settings
        RestHelper.HttpResponse response = nonSslRestHelper().executePutRequest(
            "test-index/_settings",
            "{\"index\":{\"number_of_replicas\":2}}",
            encodeBasicHeader("admin", ADMIN_PASSWORD)
        );
        log.info("Response: {}", response.getBody());
        Assert.assertEquals(200, response.getStatusCode());

        // Test user with specific index settings permission
        response = nonSslRestHelper().executePutRequest(
            "test-index/_settings",
            "{\"index\":{\"number_of_replicas\":1}}",
            encodeBasicHeader("index_settings_user", STRONG_PASSWORD)
        );
        log.info("Response: {}", response.getBody());
        Assert.assertEquals(200, response.getStatusCode());

        // Test user without index settings permission
        response = nonSslRestHelper().executePutRequest(
            "test-index/_settings",
            "{\"index\":{\"number_of_replicas\":3}}",
            encodeBasicHeader("no_settings_user", STRONG_PASSWORD)
        );
        log.info("Response: {}", response.getBody());
        Assert.assertEquals(403, response.getStatusCode());
    }

    @Test
    public void testWildcardSettingsPermissions() throws Exception {
        setupTestUsers();

        // Test user with wildcard cluster settings permission
        RestHelper.HttpResponse response = nonSslRestHelper().executePutRequest(
            "_cluster/settings",
            "{\"persistent\":{\"cluster.routing.rebalance.enable\":\"none\"}}",
            encodeBasicHeader("wildcard_settings_user", STRONG_PASSWORD)
        );
        log.info("Response: {}", response.getBody());
        Assert.assertEquals(200, response.getStatusCode());

        // Test non-matching wildcard pattern
        response = nonSslRestHelper().executePutRequest(
            "_cluster/settings",
            "{\"persistent\":{\"cluster.fault_detection.enable\":false}}",
            encodeBasicHeader("wildcard_settings_user", STRONG_PASSWORD)
        );
        log.info("Response: {}", response.getBody());
        Assert.assertEquals(403, response.getStatusCode());
    }

    private void setupTestUsers() throws Exception {
        Settings settings = Settings.builder()
            .put("plugins.security.restapi.roles_enabled", "admin")
            .build();
        setup(settings);

        // Define roles with different settings permissions
        Map<String, Object> clusterSettingsRole = new HashMap<>();
        clusterSettingsRole.put("cluster_permissions", Collections.singletonList("cluster:admin/settings/*"));
        clusterSettingsRole.put("allowed_cluster_settings", Collections.singletonList("cluster.routing.*"));
        updateSecurityConfig("roles", "cluster_settings_role", clusterSettingsRole);

        Map<String, Object> indexSettingsRole = new HashMap<>();
        Map<String, Object> indexPermission = new HashMap<>();
        indexPermission.put("index_patterns", Collections.singletonList("*"));
        indexPermission.put("allowed_actions", Collections.singletonList("indices:admin/settings/*"));
        indexPermission.put("allowed_settings", Collections.singletonList("index.number_of_replicas"));
        indexSettingsRole.put("index_permissions", Collections.singletonList(indexPermission));
        updateSecurityConfig("roles", "index_settings_role", indexSettingsRole);

        Map<String, Object> wildcardSettingsRole = new HashMap<>();
        wildcardSettingsRole.put("cluster_permissions", Collections.singletonList("cluster:admin/settings/*"));
        wildcardSettingsRole.put("allowed_cluster_settings", Collections.singletonList("cluster.routing.*"));
        updateSecurityConfig("roles", "wildcard_settings_role", wildcardSettingsRole);

        // Create users and assign roles
        createUser("cluster_settings_user", STRONG_PASSWORD, Collections.singletonList("cluster_settings_role"));
        createUser("index_settings_user", STRONG_PASSWORD, Collections.singletonList("index_settings_role"));
        createUser("wildcard_settings_user", STRONG_PASSWORD, Collections.singletonList("wildcard_settings_role"));
        createUser("no_settings_user", STRONG_PASSWORD, Collections.singletonList("kibana_user"));
    }

    private void createTestIndex() throws Exception {
        createIndex("test-index", Settings.EMPTY);
    }

    private void createIndex(String name, Settings settings) {
        CreateIndexRequest createIndexRequest = new CreateIndexRequest(name)
            .settings(settings);
        getClient().admin().indices().create(createIndexRequest).actionGet();
    }

    private void updateSecurityConfig(String configType, String name, Map<String, Object> config) {
        String endpoint = String.format("_plugins/_security/api/%s/%s", configType, name);
        try {
            String jsonBody = DefaultObjectMapper.objectMapper.writeValueAsString(config);
            RestHelper.HttpResponse response = nonSslRestHelper().executePutRequest(
                endpoint,
                jsonBody,
                encodeBasicHeader("admin", ADMIN_PASSWORD)
            );
            log.info("Response: {}", response.getBody());
            Assert.assertEquals(200, response.getStatusCode());
        } catch (Exception e) {
            Assert.fail("Failed to update security config: " + e.getMessage());
        }
    }

    private void createUser(String username, String password, List<String> roles) {
        Map<String, Object> userConfig = new HashMap<>();
        userConfig.put("password", password);
        userConfig.put("backend_roles", roles);

        String endpoint = String.format("_plugins/_security/api/internalusers/%s", username);
        try {
            String jsonBody = DefaultObjectMapper.objectMapper.writeValueAsString(userConfig);
            RestHelper.HttpResponse response = nonSslRestHelper().executePutRequest(
                    endpoint,
                    jsonBody,
                    encodeBasicHeader("admin", ADMIN_PASSWORD)
            );
            log.info("Response: {}", response.getBody());
            Assert.assertEquals(200, response.getStatusCode());
        } catch (Exception e) {
            Assert.fail("Failed to create user: " + e.getMessage());
        }
    }

    @Override
    protected String getResourceFolder() {
        return "settings_valve";
    }
}