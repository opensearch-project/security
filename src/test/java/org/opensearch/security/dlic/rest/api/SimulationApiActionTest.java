/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class SimulationApiActionTest extends AbstractRestApiUnitTest {

    @Mock
    private ClusterService clusterService;

    @Mock
    private ThreadPool threadPool;

    @Mock
    private SecurityApiDependencies securityApiDependencies;

    @Mock
    private IndexResolverReplacer irr;

    @Mock
    private IndexNameExpressionResolver indexNameExpressionResolver;

    @Mock
    private PrivilegesEvaluator privilegesEvaluator;

    @Mock
    private ConfigurationRepository configurationRepository;

    @Mock
    PrivilegesEvaluatorResponse mockResponse;

    private SimulationApiAction simulationApiAction;
    private ThreadContext threadContext;
    private RestRequest request;
    private RestChannel channel;
    private Client client;

    @Before
    public void setUp() {

        MockitoAnnotations.openMocks(this);

        threadContext = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        Settings mockSettings = Settings.builder().build();
        when(securityApiDependencies.settings()).thenReturn(mockSettings);
        when(securityApiDependencies.configurationRepository()).thenReturn(configurationRepository);

        simulationApiAction = new SimulationApiAction(
            clusterService,
            threadPool,
            securityApiDependencies,
            irr,
            indexNameExpressionResolver
        );
    }

    @Test
    public void testHandleSimulationRequest_FeatureDisabled() throws Exception {
        String requestBody = """
            {
              "action": "indices:data/read/get",
              "user": "testuser"
            }
            """;

        setupMocks(requestBody);

        Settings settings = Settings.builder().put("plugins.security.simulation_api.enabled", false).build();
        when(securityApiDependencies.settings()).thenReturn(settings);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                response -> response.status().getStatus() == 501 && response.content().utf8ToString().contains("Simulation API is disabled")
            )
        );
    }

    private void setupMocks(String requestBody) throws IOException {
        request = mock(RestRequest.class);
        when(request.content()).thenReturn(new BytesArray(requestBody));

        channel = mock(RestChannel.class);
        when(channel.newBuilder()).thenAnswer(invocation -> XContentFactory.jsonBuilder().startObject().endObject());

        client = mock(Client.class);
        simulationApiAction = spy(simulationApiAction);
    }

    @Test
    public void testHandleSimulationRequestByRoleName_ProposedConfig_AccessAllowed() throws Exception {

        String requestBody = """
              {
              "role_name": "test_role",
              "action": "indices:data/read/get",
              "roles": {
                "test_role": {
                  "index_permissions": [
                    {
                      "index_patterns": ["logs-*"],
                      "allowed_actions": ["read"]
                    }
                  ]
                }
              },
              "action_groups": {
                "read": {
                  "allowed_actions": ["indices:data/read/search", "indices:data/read/get"]
                }
              }
            }
            """;

        setupMocks(requestBody);
        when(mockResponse.isAllowed()).thenReturn(true);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of());

        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);
        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 200
                    && resp.content().utf8ToString().contains("\"accessAllowed\":true")
                    && resp.content().utf8ToString().contains("\"missingPrivileges\":[]")
            )
        );

    }

    @Test
    public void testHandleSimulationRequestByRoleName_ProposedConfig_AccessDenied() throws Exception {

        String requestBody = """
              {
              "role_name": "test_role",
              "action": "indices:data/write/index",
              "roles": {
                "test_role": {
                  "index_permissions": [
                    {
                      "index_patterns": ["logs-*"],
                      "allowed_actions": ["read"]
                    }
                  ]
                }
              },
              "action_groups": {
                "read": {
                  "allowed_actions": ["indices:data/read/search", "indices:data/read/get"]
                }
              }
            }
            """;

        setupMocks(requestBody);
        when(mockResponse.isAllowed()).thenReturn(false);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of("indices:data/write/index"));

        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);
        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 200
                    && resp.content().utf8ToString().contains("\"accessAllowed\":false")
                    && resp.content().utf8ToString().contains("\"missingPrivileges\":[\"indices:data/write/index\"]")
            )
        );

    }

    @Test
    public void testHandleSimulationRequestByRoleName_CurrentConfig_AccessAllowed() throws Exception {
        String requestBody = """
            {
              "role_name": "test_role",
              "action": "indices:data/read/get",
              "index": "logs-2024"
            }
            """;

        setupMocks(requestBody);

        when(mockResponse.isAllowed()).thenReturn(true);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of());

        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);

        when(securityApiDependencies.configurationRepository()).thenReturn(configurationRepository);
        when(configurationRepository.getConfiguration(eq(CType.ROLES))).thenReturn(
            SecurityDynamicConfiguration.fromMap(Map.of("test_role", new RoleV7()), CType.ROLES)
        );
        when(configurationRepository.getConfiguration(eq(CType.ACTIONGROUPS))).thenReturn(
            SecurityDynamicConfiguration.fromMap(Map.of(), CType.ACTIONGROUPS)
        );

        simulationApiAction.handleSimulationRequest(channel, request, client);

        // Debug: Check what error message is being sent
        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 200
                    && resp.content().utf8ToString().contains("\"accessAllowed\":true")
                    && resp.content().utf8ToString().contains("\"missingPrivileges\":[]")
            )
        );
    }

    @Test
    public void testHandleSimulationRequestByRoleName_CurrentConfig_AccessDenied() throws Exception {
        String requestBody = """
            {
              "role_name": "test_role",
              "action": "indices:data/write/index",
              "index": "logs-2024"
            }
            """;

        setupMocks(requestBody);

        when(mockResponse.isAllowed()).thenReturn(false);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of("indices:data/write/index"));
        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);

        when(securityApiDependencies.configurationRepository()).thenReturn(configurationRepository);
        when(configurationRepository.getConfiguration(eq(CType.ROLES))).thenReturn(
            SecurityDynamicConfiguration.fromMap(Map.of("test_role", new RoleV7()), CType.ROLES)
        );
        when(configurationRepository.getConfiguration(eq(CType.ACTIONGROUPS))).thenReturn(
            SecurityDynamicConfiguration.fromMap(Map.of(), CType.ACTIONGROUPS)
        );

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 200
                    && resp.content().utf8ToString().contains("\"accessAllowed\":false")
                    && resp.content().utf8ToString().contains("\"missingPrivileges\":[\"indices:data/write/index\"]")
            )
        );
    }

    @Test
    public void testHandleSimulationRequestUserBased_ProposedConfig_ActionAllowed() throws Exception {
        String requestBody = """
            {
              "action": "indices:data/read/get",
              "user": "testuser",
              "roles": {
                "test_role": {
                  "index_permissions": [
                    {
                      "index_patterns": ["logs-*"],
                      "allowed_actions": ["read"]
                    }
                  ]
                }
              },
              "roles_mapping": {
                "test_role": {
                  "users": ["testuser"]
                }
              },
              "action_groups": {
                "read": {
                  "allowed_actions": ["indices:data/read/search", "indices:data/read/get"]
                }
              }
            }
            """;
        setupMocks(requestBody);
        when(mockResponse.isAllowed()).thenReturn(true);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of());

        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 200
                    && resp.content().utf8ToString().contains("\"accessAllowed\":true")
                    && resp.content().utf8ToString().contains("\"missingPrivileges\":[]")
            )
        );
    }

    @Test
    public void testHandleSimulationRequestUserBased_ProposedConfig_ActionDenied() throws Exception {
        String requestBody = """
            {
              "action": "indices:data/write/index",
              "user": "test-user",
              "roles": {
                "test_role": {
                  "index_permissions": [
                    {
                      "index_patterns": ["logs-*"],
                      "allowed_actions": ["read"]
                    }
                  ]
                }
              },
              "roles_mapping": {
                "test_role": {
                  "users": ["test-user"]
                }
              },
              "action_groups": {
                "read": {
                  "allowed_actions": ["indices:data/read/search", "indices:data/read/get"]
                }
              }
            }
            """;
        setupMocks(requestBody);
        when(mockResponse.isAllowed()).thenReturn(false);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of("indices:data/write/index"));

        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 200
                    && resp.content().utf8ToString().contains("\"accessAllowed\":false")
                    && resp.content().utf8ToString().contains("\"missingPrivileges\":[\"indices:data/write/index\"]")
            )
        );
    }

    @Test
    public void testHandleSimulationRequestUserBased_WithCurrentConfig_AccessAllowed() throws Exception {
        String requestBody = """
            {
              "action": "indices:data/write/index",
              "index": "logs-2024",
              "user": "test-user"
            }
            """;

        setupMocks(requestBody);

        // Mock denied access
        when(mockResponse.isAllowed()).thenReturn(true);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of());

        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.mapRoles(any(), any())).thenReturn(Set.of("test_role"));
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);
        when(privilegesEvaluator.createContext(any(), any())).thenReturn(
            mock(org.opensearch.security.privileges.PrivilegesEvaluationContext.class)
        );

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 200
                    && resp.content().utf8ToString().contains("\"accessAllowed\":true")
                    && resp.content().utf8ToString().contains("\"missingPrivileges\":[]")
            )
        );
    }

    @Test
    public void testHandleSimulationRequestUserBased_WithCurrentConfig_AccessDenied() throws Exception {
        String requestBody = """
            {
              "action": "indices:data/write/index",
              "index": "logs-2024",
              "user": "test-user"
            }
            """;

        setupMocks(requestBody);

        // Mock denied access
        when(mockResponse.isAllowed()).thenReturn(false);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of("indices:data/write/index"));

        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.mapRoles(any(), any())).thenReturn(Set.of("test_role"));
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);
        when(privilegesEvaluator.createContext(any(), any())).thenReturn(
            mock(org.opensearch.security.privileges.PrivilegesEvaluationContext.class)
        );

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 200
                    && resp.content().utf8ToString().contains("\"accessAllowed\":false")
                    && resp.content().utf8ToString().contains("\"missingPrivileges\":[\"indices:data/write/index\"]")
            )
        );
    }

    @Test
    public void testHandleSimulationRequest_MissingBothUserAndRole() throws Exception {
        String requestBody = """
            {
              "action": "indices:data/read/get"
            }
            """;

        setupMocks(requestBody);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 400
                    && resp.content().utf8ToString().contains("Either 'role_name' or 'user' must be provided to simulate permissions.")
            )
        );
    }

    @Test
    public void testHandleSimulationRequest_MissingAction() throws Exception {
        String requestBody = """
            {
              "role_name": "test_role"
            }
            """;
        setupMocks(requestBody);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                resp -> resp.status().getStatus() == 400
                    && resp.content()
                        .utf8ToString()
                        .contains("Missing required field: 'action'. Action field is required for permission simulation")
            )
        );
    }

    @Test
    public void testHandleSimulationRequest_EmptyAction() throws Exception {
        String requestBody = """
            {
               "action": " "
            }
            """;
        setupMocks(requestBody);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                response -> response.status().getStatus() == 400
                    && response.content()
                        .utf8ToString()
                        .contains("Missing required field: 'action'. Action field is required for permission simulation")
            )
        );
    }

    @Test
    public void testHandleSimulationRequest_RequestEmpty() throws Exception {
        String requestBody = "";
        setupMocks(requestBody);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(
            argThat(
                response -> response.status().getStatus() == 400
                    && response.content().utf8ToString().contains("Request body cannot be empty")
            )
        );
    }

}
