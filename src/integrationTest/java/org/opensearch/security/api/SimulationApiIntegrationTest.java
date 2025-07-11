package org.opensearch.security.api;

import java.util.Map;

import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class SimulationApiIntegrationTest extends AbstractApiIntegrationTest {

    static {
        testSecurityConfig.user(new TestSecurityConfig.User("test-user").password("password"))
            .roles(new TestSecurityConfig.Role("test_role").indexPermissions("indices:data/read/*").on("logs-*"))
            .rolesMapping(new TestSecurityConfig.RoleMapping("test_role").users("test-user"));
    }

    @Override
    protected Map<String, Object> getClusterSettings() {
        Map<String, Object> settings = super.getClusterSettings();
        settings.put("plugins.security.simulation_api.enabled", true);
        return settings;
    }

    private String simulationEndpoint() {
        return PLUGINS_PREFIX + "/api/simulation";
    }

    @Test
    public void testSimulateWithRole_CurrentConfig_ActionAllowed() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/read/search",
                  "role_name": "test_role",
                  "index": "logs-2024"
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getBooleanFromJsonBody("/accessAllowed"), is(true));
        });
    }

    @Test
    public void testSimulateWithRole_CurrentConfig_ActionDenied() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/read/search",
                  "role_name": "user_test_role",
                  "index": "test-2024"
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getBooleanFromJsonBody("/accessAllowed"), is(false));
        });
    }

    @Test
    public void testSimulateWithRole_ProposedConfig_ActionAllowed() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/read/search",
                  "role_name": "user_test_role",
                  "index": "test-2024",
                  "roles": {
                        "user_test_role": {
                              "index_permissions": [{
                                   "index_patterns": ["test-*"],
                                       "allowed_actions": ["indices:data/read/*"]
                              }]
                        }
                  }
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getBooleanFromJsonBody("/accessAllowed"), is(true));
        });
    }

    @Test
    public void testSimulateWithRole_ProposedConfig_ActionDenied() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/write/index",
                  "role_name": "user_test_role",
                  "index": "test-2024",
                  "roles": {
                        "user_test_role": {
                              "index_permissions": [{
                                   "index_patterns": ["test-*"],
                                       "allowed_actions": ["indices:data/read/*"]
                              }]
                        }
                  }
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getBooleanFromJsonBody("/accessAllowed"), is(false));
            assertThat(response.getBody(), containsString("\"missingPrivileges\":[\"indices:data/write/index\"]"));
        });
    }

    @Test
    public void testSimulateWithUser_ProposedConfig_ActionAllowed() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/read/search",
                  "user":"test-user",
                  "index": "test-2024",
                  "roles": {
                        "user_test_role": {
                              "index_permissions": [{
                                   "index_patterns": ["test-*"],
                                          "allowed_actions": ["indices:data/read/*"]
                                        }]
                                      }
                                       },
                  "roles_mapping": {
                        "user_test_role": {
                              "users": ["test-user"]
                              }
                        }
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getBooleanFromJsonBody("/accessAllowed"), is(true));
        });
    }

    @Test
    public void testSimulateWithUser_ProposedConfig_ActionDenied() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/read/search",
                  "user":"test-user",
                  "index": "logs-2024",
                  "roles": {
                        "user_test_role": {
                              "index_permissions": [{
                                   "index_patterns": ["test-*"],
                                          "allowed_actions": ["indices:data/read/*"]
                                        }]
                                   }
                              },
                  "roles_mapping": {
                        "user_test_role": {
                              "users": ["test-user"]
                              }
                        }
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getBooleanFromJsonBody("/accessAllowed"), is(false));
            assertThat(response.getBody(), containsString("\"missingPrivileges\":[\"indices:data/read/search\"]"));

        });
    }

    @Test
    public void testSimulateWithUser_CurrentConfig_ActionAllowed() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/read/get",
                  "user":"test-user",
                  "index": "logs-2024"
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getBooleanFromJsonBody("/accessAllowed"), is(true));

        });
    }

    @Test
    public void testSimulateWithUser_CurrentConfig_ActionDenied() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/write/index",
                  "user":"test-user",
                  "index": "logs-2024"
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getBooleanFromJsonBody("/accessAllowed"), is(false));
            assertThat(response.getBody(), containsString("\"missingPrivileges\":[\"indices:data/write/index\"]"));

        });
    }

    @Test
    public void testSimulate_missingAction() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "user": "test-user",
                  "index": "logs-2024"
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
            assertThat(response.getTextFromJsonBody("/message"), containsString("Missing required field: 'action'"));
        });
    }

    @Test
    public void testSimulate_missingUserAndRole() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/read/search",
                  "index": "logs-2024"
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
            assertThat(response.getTextFromJsonBody("/message"), containsString("Either 'role_name' or 'user' must be provided"));
        });
    }

    @Test
    public void testSimulate_emptyBody() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            var response = client.postJson(simulationEndpoint(), "");
            assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
            assertThat(response.getTextFromJsonBody("/message"), containsString("Request body cannot be empty"));
        });
    }

    @Test
    public void testSimulate_responseStructure() throws Exception {
        withUser(ADMIN_USER_NAME, DEFAULT_PASSWORD, client -> {
            String requestBody = """
                {
                  "action": "indices:data/read/search",
                  "user": "test-user",
                  "index": "logs-2024"
                }
                """;

            var response = client.postJson(simulationEndpoint(), requestBody);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(response.getBody(), containsString("accessAllowed"));
            assertThat(response.getBody(), containsString("missingPrivileges"));
        });
    }

}
