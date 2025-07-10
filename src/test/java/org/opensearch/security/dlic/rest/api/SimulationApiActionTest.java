package org.opensearch.security.dlic.rest.api;
import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;

import org.mockito.MockitoAnnotations;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.configuration.ConfigurationMap;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.common.util.concurrent.ThreadContext;

import java.io.IOException;
import java.util.*;

import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.action.search.*;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
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
    PrivilegesEvaluationContext mockContext;

    @Mock
    private ConfigurationRepository configurationRepository;

    @Mock
    ActionPrivileges mockActionPrivileges;

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

        when(threadPool.getThreadContext()).thenReturn(threadContext);
        Settings mockSettings = Settings.builder().build();
        when(securityApiDependencies.settings()).thenReturn(mockSettings);

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

        Settings settings = Settings.builder()
                .put("plugins.security.simulation_api.enabled", false)
                .build();
        when(securityApiDependencies.settings()).thenReturn(settings);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(argThat(response ->
                response.status().getStatus() == 501 &&
                        response.content().utf8ToString().contains("Simulation API is experimental and disabled")
        ));
    }

    @Test
    public void testHandleSimulationRequest_AdminUserNotAllowed() throws Exception {
        String requestBody = """
        {
          "action": "indices:data/read/get",
          "user": "admin"
        }
        """;

        setupMocks(requestBody);

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(argThat(response ->
                response.status().getStatus() == 400 &&
                        response.content().utf8ToString().contains("Permission simulation for admin user is not allowed")
        ));
    }

    @Test
    public void testCreateActionRequestFromAction() {

        String action1 = "indices:data/write/update";
        String action2 = "indices:data/read/search";
        String action3 = "indices:data/read/scroll";

        String index = "test-index";
        String id="doc1";
        ActionRequest request1 = simulationApiAction.createActionRequest(action1,index,id);
        ActionRequest request2 = simulationApiAction.createActionRequest(action2,index,null);
        ActionRequest request3 = simulationApiAction.createActionRequest(action3, null, null);

        assertThat(request1, instanceOf(UpdateRequest.class));
        assertThat(request2, instanceOf(SearchRequest.class));
        assertThat(request3, instanceOf(SearchScrollRequest.class));

    }

    @Test
    public void testCreateActionRequestWithUnknownAction() {

        ActionRequest request = simulationApiAction.createActionRequest(
                "unknown/action",
                "test-index",
                null
        );

        assertThat(request, notNullValue());
        assertThat(request, instanceOf(ActionRequest.class));
        assertNull(request.validate());

    }

    @Test
    public void testGetMappedRolesForUser() {

        //single role assigned to user
        User testUser = new User("test-user");
        Map<String, Object> roleMappings = new HashMap<>();

        Map<String, Object> observabilityRoleMapping = new HashMap<>();
        observabilityRoleMapping.put("users", Arrays.asList("admin", "test-user"));
        roleMappings.put("observability_read_access", observabilityRoleMapping);

        ImmutableSet<String> result = simulationApiAction.getMappedRolesForUser(testUser, roleMappings);

        assertThat(result, hasSize(1));
        assertThat(result, hasItem("observability_read_access"));

        // multiple roles assigned to user
        Map<String, Object> readerRoleMapping = new HashMap<>();
        readerRoleMapping.put("users", List.of("test-user"));
        roleMappings.put("reader_role", readerRoleMapping);

        result = simulationApiAction.getMappedRolesForUser(testUser, roleMappings);

        assertThat(result, hasSize(2));
        assertThat(result, containsInAnyOrder("reader_role", "observability_read_access"));

        // No roles assigned to user
        testUser = new User("xyz");
        result = simulationApiAction.getMappedRolesForUser(testUser, roleMappings);

        assertThat(result, hasSize(0));
        assertTrue(result.isEmpty());

    }

    @Test
    public void testGetMappedRolesForUserExceptions() {
        User testUser = new User("test-user");
        assertThrows(RuntimeException.class, () ->
                simulationApiAction.getMappedRolesForUser(testUser, null)
        );
        Map<String, Object> invalidMappings = Map.of(
                "bad_role", "invalid"
        );
        assertThrows(RuntimeException.class, () ->
                simulationApiAction.getMappedRolesForUser(testUser, invalidMappings)
        );
    }

    @Test
    public void testGetMappedRolesForUserEdgeCases() {
        User testUser = new User("test-user");
        Map<String, Object> validMappings = Map.of(
                "test_role", Map.of("users", List.of("test-user"))
        );
        assertThrows(NullPointerException.class, () ->
                simulationApiAction.getMappedRolesForUser(null, validMappings)
        );

        ImmutableSet<String> result = simulationApiAction.getMappedRolesForUser(testUser, Map.of());
        assertThat(result, hasSize(0));

        Map<String, Object> noUsersMappings = Map.of(
                "backend_role", Map.of("backend_roles", List.of("admin"))
        );
        result = simulationApiAction.getMappedRolesForUser(testUser, noUsersMappings);
        assertThat(result, hasSize(0));
    }


    @Test
    public void testCreateActionPrivilegesWithValidConfig() throws IOException {

        Map<String, Object> roles = Map.of(
                "observability_read_access", Map.of(
                        "cluster_permissions", List.of(),
                        "index_permissions", List.of(
                                Map.of(
                                        "index_patterns", List.of("logs-*"),
                                        "allowed_actions", List.of("read")
                                )
                        ),
                        "tenant_permissions", List.of()
                )
        );

        Map<String, Object> actionGroups = Map.of(
                "read", Map.of(
                        "allowed_actions", List.of(
                                "indices:data/read/search",
                                "indices:data/read/get"
                        )
                )
        );

        Settings settings = Settings.builder().build();   //empty settings

        ActionPrivileges privileges = simulationApiAction.createActionPrivileges(
                roles,
                actionGroups,
                settings
        );

        assertThat(privileges, is(notNullValue()));
        assertThat(privileges, instanceOf(RoleBasedActionPrivileges.class));

    }

    @Test
    public void testCreateActionPrivilegesWithEmptyConfig() throws IOException {

        Map<String, Object> roles = Map.of();
        Map<String, Object> actionGroups = Map.of();

        Settings settings = Settings.builder().build();   //empty settings

        ActionPrivileges privileges = simulationApiAction.createActionPrivileges(
                roles,
                actionGroups,
                settings
        );

        assertThat(privileges, is(notNullValue()));
        assertThat(privileges, instanceOf(RoleBasedActionPrivileges.class));

    }
    @Test
    public void testCreateActionPrivilegesIOException() {
        Map<String, Object> invalidRoles = Map.of("role", "invalid_structure");

        assertThrows(RuntimeException.class, () ->
                simulationApiAction.createActionPrivileges(invalidRoles, Map.of(), Settings.EMPTY)
        );

    }


    @Test
    public void testCreatePrivilegesEvaluationContext() {

        Map<String, Object> proposedBody = Map.of(
                "user", "test-user",
                "action", "indices:data/read/search",
                "index", "logs-*",
                "roles", Map.of(
                        "read_role", Map.of(
                                "cluster_permissions", List.of(),
                                "index_permissions", List.of(
                                        Map.of(
                                                "index_patterns",List.of("*"),
                                                "allowed_actions",List.of("indices:data/write/index")
                                        )
                                ),
                                "tenant_permissions", List.of()

                        )
                ),
                "roles_mapping", Map.of(
                        "read_role", Map.of("users", List.of("test-user"))
                )
        );

        when(threadPool.getThreadContext()).thenReturn(threadContext);

        PrivilegesEvaluationContext context = simulationApiAction.createPrivilegesEvaluationContext(
                proposedBody, clusterService, irr, indexNameExpressionResolver, mockActionPrivileges
        );

        assertThat(context.getUser().getName(), is("test-user"));
        assertThat(context.getAction(), is("indices:data/read/search"));
        assertThat(context.getMappedRoles(), containsInAnyOrder("read_role"));

    }


    @Test
    public void testEvaluateWithProposedConfig_AllowedAction(){

        Map<String, Object> proposedBody = Map.of(
                "user", "test-user",
                "action", "indices:data/read/search",
                "index", "logs-2024",
                "roles", Map.of(
                        "read_role", Map.of(
                                "cluster_permissions", List.of(),
                                "index_permissions", List.of(
                                        Map.of(
                                                "index_patterns", List.of("logs-*"),
                                                "allowed_actions", List.of("read")
                                        )
                                ),
                                "tenant_permissions", List.of()
                        )
                ),
                "roles_mapping", Map.of(
                        "read_role", Map.of("users", List.of("test-user"))
                ),
                "action_groups", Map.of(
                        "read", Map.of(
                                "allowed_actions", List.of(
                                        "indices:data/read/search",
                                        "indices:data/read/get"
                                )
                        )
                )
        );

        when(threadPool.getThreadContext()).thenReturn(threadContext);

        when(mockResponse.isAllowed()).thenReturn(true);

        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);

        // Call the actual method
        PrivilegesEvaluatorResponse response = simulationApiAction.evaluateWithProposedConfig(proposedBody);

        assertThat("Action should be allowed", response.isAllowed(), is(true));
        assertThat("Should have no missing privileges", response.getMissingPrivileges(), empty());

    }

    @Test
    public void testEvaluateWithProposedConfig_DeniedAction() {

        Map<String, Object> proposedBody = Map.of(
                "user", "test-user",
                "action", "indices:data/write/index",
                "index", "logs-2024",
                "roles", Map.of(
                        "read_role", Map.of(
                                "cluster_permissions", List.of(),
                                "index_permissions", List.of(
                                        Map.of(
                                                "index_patterns", List.of("logs-*"),
                                                "allowed_actions", List.of("read")
                                        )
                                ),
                                "tenant_permissions", List.of()
                        )
                ),
                "roles_mapping", Map.of(
                        "read_role", Map.of("users", List.of("test-user"))
                ),
                "action_groups", Map.of(
                        "read", Map.of(
                                "allowed_actions", List.of(
                                        "indices:data/read/search",
                                        "indices:data/read/get"
                                )
                        )
                )
        );

        when(threadPool.getThreadContext()).thenReturn(threadContext);

        when(mockResponse.isAllowed()).thenReturn(false);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of("indices:data/write/index"));

        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);

        // Call the actual method
        PrivilegesEvaluatorResponse response = simulationApiAction.evaluateWithProposedConfig(proposedBody);

        assertThat("Action should be denied", response.isAllowed(), is(false));
        assertThat("Should return missing privileges", response.getMissingPrivileges(),
                hasItem("indices:data/write/index"));

    }

    private void setupCurrentConfigMocks() {
        ConfigurationMap mockConfigMap = mock(ConfigurationMap.class);
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<RoleV7> mockRolesConfig = mock(SecurityDynamicConfiguration.class);
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<ActionGroupsV7> mockActionGroupsConfig = mock(SecurityDynamicConfiguration.class);

        when(securityApiDependencies.configurationRepository()).thenReturn(configurationRepository);
        when(configurationRepository.getConfigurationsFromIndex(any(), anyBoolean())).thenReturn(mockConfigMap);
        when(mockConfigMap.get(CType.ROLES)).thenReturn(mockRolesConfig);
        when(mockConfigMap.get(CType.ACTIONGROUPS)).thenReturn(mockActionGroupsConfig);
        when(mockRolesConfig.deepClone()).thenReturn(mockRolesConfig);
        when(mockActionGroupsConfig.deepClone()).thenReturn(mockActionGroupsConfig);
    }


    @Test
    public void testEvaluateByRoleNameWithCurrentConfig_AllowedAction() throws IOException {
        Map<String, Object> proposedBody = Map.of(
                "action", "indices:data/write/update",
                "index", "test-index"
        );

        setupCurrentConfigMocks();
        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.evaluate(any(PrivilegesEvaluationContext.class))).thenReturn(mockResponse);
        when(mockResponse.isAllowed()).thenReturn(true);

        PrivilegesEvaluatorResponse result = simulationApiAction.evaluateByRoleName(
                proposedBody, "existing_role", false
        );

        assertThat(result.isAllowed(), is(true));
    }

    @Test
    public void testEvaluateByRoleNameWithCurrentConfig_Denied() throws IOException {
        Map<String, Object> proposedBody = Map.of(
                "action", "indices:data/write/update",
                "index", "test-index"
        );

        setupCurrentConfigMocks();
        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.evaluate(any(PrivilegesEvaluationContext.class))).thenReturn(mockResponse);

        when(mockResponse.isAllowed()).thenReturn(false);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of("indices:data/write/update"));

        PrivilegesEvaluatorResponse result = simulationApiAction.evaluateByRoleName(
                proposedBody, "existing_role", false
        );

        assertThat(result.isAllowed(), is(false));
        assertThat(result.getMissingPrivileges(), hasItem("indices:data/write/update"));
    }


    @Test
    public void testEvaluateByRoleName_AllowedAction() throws IOException {
        Map<String, Object> proposedBody = Map.of(
                "role_name", "test_role",
                "action", "indices:data/read/get",
                "index", "logs-test",
                "roles", Map.of(
                        "test_role", Map.of(
                                "index_permissions", List.of(
                                        Map.of(
                                                "index_patterns", List.of("logs-*"),
                                                "allowed_actions", List.of("read")
                                        )
                                )
                        )
                ),
                "action_groups", Map.of(
                        "read", Map.of(
                                "allowed_actions", List.of(
                                        "indices:data/read/search",
                                        "indices:data/read/get"
                                )
                        )
                )
        );
        boolean hasProposedConfig = proposedBody.containsKey("roles") || proposedBody.containsKey("action_groups");
        String roleName = (String) proposedBody.get("role_name");
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        when(mockResponse.isAllowed()).thenReturn(true);

        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);

        PrivilegesEvaluatorResponse response = simulationApiAction.evaluateByRoleName(proposedBody, roleName, hasProposedConfig);

        assertThat(response.isAllowed(), is(true));
        assertThat(response.getMissingPrivileges(), empty());

    }
    private void setupMocks(String requestBody) throws IOException {
        request = mock(RestRequest.class);
        when(request.content()).thenReturn(new BytesArray(requestBody));

        channel = mock(RestChannel.class);
        // Create a fresh builder each time
        when(channel.newBuilder()).thenAnswer(invocation ->
                XContentFactory.jsonBuilder().startObject().endObject());

        // Enable simulation API by default in setupMocks
        Settings settings = Settings.builder()
                .put("plugins.security.simulation_api.enabled", true)
                .build();
        when(securityApiDependencies.settings()).thenReturn(settings);

        mockResponse = mock(PrivilegesEvaluatorResponse.class);
        when(mockResponse.isAllowed()).thenReturn(true);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of());

        client = mock(Client.class);
        simulationApiAction = spy(simulationApiAction);
    }



    @Test
    public void testHandleSimulationRequest_WithRoleName_UsingProposedConfig() throws Exception {

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
        doReturn(mockResponse).when(simulationApiAction).evaluateByRoleName(any(), eq("test_role"), anyBoolean());

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(argThat(resp->
                resp.status().getStatus() == 200 &&
                resp.content().utf8ToString().contains("\"accessAllowed\":true")
            ));

    }

    @Test
    public void testHandleSimulationRequest_WithRoleName_UsingCurrentConfig() throws Exception {
        String requestBody = """
        {
          "role_name": "test_role",
          "action": "indices:data/read/get",
          "index": "logs-2024"
        }
        """;

        setupMocks(requestBody);
        when(securityApiDependencies.configurationRepository()).thenReturn(configurationRepository);
        doReturn(mockResponse).when(simulationApiAction).evaluateByRoleName(any(), eq("test_role"), eq(false));

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(argThat(resp ->
                resp.status().getStatus() == 200 &&
                        resp.content().utf8ToString().contains("\"accessAllowed\":true")
        ));
    }


    @Test
    public void testHandleSimulationRequestUserBased_WithProposedConfig() throws Exception {
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

        doReturn(mockResponse).when(simulationApiAction).evaluateWithProposedConfig(any());
        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(argThat(resp ->
                resp.status().getStatus() == 200 &&
                resp.content().utf8ToString().contains("\"accessAllowed\":true")
        ));
    }

    @Test
    public void testHandleSimulationRequestUserBased_WithCurrentConfig() throws Exception {
        String requestBody = """
        {
          "action": "indices:data/read/get",
          "index": "logs-2024",
          "user": "testuser"
        }
        """;

        setupMocks(requestBody);

        doReturn(mockResponse).when(simulationApiAction).evaluateWithCurrentConfig(any());

        simulationApiAction.handleSimulationRequest(channel, request, client);

        verify(channel).sendResponse(argThat(resp ->
                resp.status().getStatus() == 200 &&
                        resp.content().utf8ToString().contains("\"accessAllowed\":true")
        ));
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

        verify(channel).sendResponse(argThat(resp ->
                resp.status().getStatus() == 400 &&
                        resp.content().utf8ToString().contains("Either 'role_name' or 'user' must be provided to simulate permissions.")
        ));
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

        verify(channel).sendResponse(argThat(resp ->
                resp.status().getStatus() == 400 &&
                        resp.content().utf8ToString().contains("Missing required field: 'action'. Action field is required for permission simulation")
        ));
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

        verify(channel).sendResponse(argThat(response ->
                response.status().getStatus() == 400 &&
                        response.content().utf8ToString().contains("Missing required field: 'action'. Action field is required for permission simulation")
        ));
    }

    private void setupCurrentConfigEvaluation(String action) {
        simulationApiAction = spy(simulationApiAction);
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        when(securityApiDependencies.privilegesEvaluator()).thenReturn(privilegesEvaluator);
        when(privilegesEvaluator.createContext(any(), eq(action))).thenReturn(mockContext);
        when(mockContext.getActionPrivileges()).thenReturn(mockActionPrivileges);
        when(privilegesEvaluator.mapRoles(any(), any())).thenReturn(Set.of("reader-role"));
        when(privilegesEvaluator.evaluate(any())).thenReturn(mockResponse);
    }


    @Test
    public void testEvaluateWithCurrentConfig_AllowedAction(){
        Map<String, Object> requestBody = Map.of(
                "action", "indices:data/read/get",
                "index","logs-test",
                "user", "test-user"
        );
        String action= (String) requestBody.get("action");
        setupCurrentConfigEvaluation(action);
        when(mockResponse.isAllowed()).thenReturn(true);

        PrivilegesEvaluatorResponse response = simulationApiAction.evaluateWithCurrentConfig(requestBody);

        assertTrue(response.isAllowed());
        verify(privilegesEvaluator).createContext(any(), eq("indices:data/read/get"));

    }

    @Test
    public void testEvaluateWithCurrentConfig_DeniedAction() {
        Map<String, Object> requestBody = Map.of(
                "action", "indices:data/write/index",
                "index","logs-test",
                "user", "test-user"
        );

        String action= (String) requestBody.get("action");
        setupCurrentConfigEvaluation(action);
        when(mockResponse.isAllowed()).thenReturn(false);
        when(mockResponse.getMissingPrivileges()).thenReturn(Set.of("indices:data/write/index"));

        PrivilegesEvaluatorResponse response = simulationApiAction.evaluateWithCurrentConfig(requestBody);

        assertFalse("Access should be denied", response.isAllowed());
        assertThat(response.getMissingPrivileges(), containsInAnyOrder("indices:data/write/index"));

        verify(privilegesEvaluator).createContext(any(), eq(action));
    }

}
