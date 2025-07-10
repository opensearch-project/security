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

import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.explain.ExplainRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.*;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import java.io.IOException;
import java.util.*;
import java.util.function.Supplier;
import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.internalServerError;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import com.google.common.collect.ImmutableList;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

/**
 * Simulation API for simulating user and role-based permissions at index and cluster levels.
 * Allows administrators to preview permissions before applying configuration changes.
 *
 * <p><strong>Endpoint:</strong>  POST /_plugins/_security/api/simulation</p>
 *
 * <p><strong>EXPERIMENTAL:</strong> This API is experimental and may change in future versions.
 * Enable with plugins.security.simulation_api.enabled=true</p>
 *
 */
public class SimulationApiAction extends AbstractApiAction {

    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
            new Route(RestRequest.Method.POST, "/simulation")
    ));

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final IndexResolverReplacer irr;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    private static final String ROLES = "roles";
    private static final String ROLES_MAPPING = "roles_mapping";
    private static final String ACTION_GROUPS = "action_groups";
    private static final String ACTION = "action";
    private static final String INDEX = "index";
    private static final String ID = "id";
    private static final String USER="user";
    private static final String ROLE_NAME="role_name";

    public SimulationApiAction(ClusterService clusterService,
                               ThreadPool threadPool,
                               SecurityApiDependencies securityApiDependencies,
                               IndexResolverReplacer irr,
                               IndexNameExpressionResolver indexNameExpressionResolver)  {
        super(Endpoint.SIMULATION, clusterService, threadPool, securityApiDependencies);
        this.irr = irr;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.requestHandlersBuilder.add(RestRequest.Method.POST, this::handleSimulationRequest);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType<?> getConfigType() {
        return null;
    }

    public void handleSimulationRequest(RestChannel channel, RestRequest request, Client client){
        boolean simulationApiEnabled = securityApiDependencies.settings().getAsBoolean(
                ConfigConstants.EXPERIMENTAL_SECURITY_SIMULATION_API_ENABLED,
                ConfigConstants.EXPERIMENTAL_SECURITY_SIMULATION_API_ENABLED_DEFAULT
        );

        if (!simulationApiEnabled) {
            ValidationResult<Map<String, Object>> featureDisabledResult = ValidationResult.error(
                    RestStatus.NOT_IMPLEMENTED,
                    payload(RestStatus.NOT_IMPLEMENTED, "Simulation API is experimental and disabled by default. Enable with plugins.security.simulation_api.enabled=true")
            );
            sendErrorResponse(channel, featureDisabledResult);
            return;
        }

        ValidationResult<Map<String, Object>> validationResult = validateRequest(request);
        if (!validationResult.isValid()) {
            sendErrorResponse(channel, validationResult);
            return;
        }

        try {

            Map<String, Object> proposedBody = parseRequest(request);
            PrivilegesEvaluatorResponse response;

            String roleName = (String) proposedBody.get(ROLE_NAME);
            boolean hasRoles = proposedBody.containsKey(ROLES);
            boolean hasRoleMapping = proposedBody.containsKey(ROLES_MAPPING);

            if (roleName != null && !roleName.isEmpty()) {
                response = evaluateByRoleName(proposedBody, roleName, hasRoles || proposedBody.containsKey(ACTION_GROUPS));
            } else if (hasRoles && hasRoleMapping) {
                response = evaluateWithProposedConfig(proposedBody);
            } else {
                response = evaluateWithCurrentConfig(proposedBody);
            }

            // Build response
            XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            builder.field("accessAllowed", response.isAllowed());
            builder.field("missingPrivileges", response.getMissingPrivileges());
            builder.endObject();

            channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));

        } catch (Exception e) {
            ValidationResult<PrivilegesEvaluatorResponse> errorResult = ValidationResult.error(
                    RestStatus.INTERNAL_SERVER_ERROR, payload(RestStatus.INTERNAL_SERVER_ERROR, "Failed to simulate permissions: " + e.getMessage())
            );
            sendErrorResponse(channel, errorResult);
        }

    }
    public  Map<String, Object> parseRequest(RestRequest request) throws IOException {
        return DefaultObjectMapper.objectMapper.readValue(
                request.content().utf8ToString(),
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
                }
        );
    }
    private ValidationResult<Map<String, Object>> validateRequest(RestRequest request) {
        try {
            if (request.content() == null || request.content().length() == 0) {
                return ValidationResult.error(RestStatus.BAD_REQUEST,
                        payload(RestStatus.BAD_REQUEST, "Request body cannot be empty"));
            }

            Map<String, Object> proposedBody = parseRequest(request);

            // Validate action field
            String action = (String) proposedBody.get(ACTION);
            if (action == null || action.trim().isEmpty()) {
                return ValidationResult.error(RestStatus.BAD_REQUEST,
                        payload(RestStatus.BAD_REQUEST, "Missing required field: 'action'. Action field is required for permission simulation"));
            }
            String roleName = (String) proposedBody.get(ROLE_NAME);
            String simulatedUserName = (String) proposedBody.get(USER);

            if ((roleName == null || roleName.trim().isEmpty()) &&
                    (simulatedUserName == null || simulatedUserName.trim().isEmpty())) {
                return ValidationResult.error(
                        RestStatus.BAD_REQUEST,
                        payload(
                                RestStatus.BAD_REQUEST,
                                "Either 'role_name' or 'user' must be provided to simulate permissions."
                        )
                );
            }
            if (simulatedUserName != null && "admin".equals(simulatedUserName.trim())) {
                return ValidationResult.error(
                        RestStatus.BAD_REQUEST,
                        payload(
                                RestStatus.BAD_REQUEST,
                                "Permission simulation for admin user is not allowed"
                        )
                );
            }
            return ValidationResult.success(proposedBody);
        } catch (Exception e) {
            return ValidationResult.error(RestStatus.BAD_REQUEST,
                    payload(RestStatus.BAD_REQUEST, "Invalid request: " + e.getMessage()));
        }
    }

    private void sendErrorResponse(RestChannel channel, ValidationResult<?> validationResult) {
        try {
            validationResult.error((status, errorMessage) -> {
                XContentBuilder builder = channel.newBuilder();
                errorMessage.toXContent(builder, null);
                channel.sendResponse(new BytesRestResponse(status, builder));
            });
        } catch (IOException e) {
            log.error("Failed to send error response", e);
            internalServerError(channel, "Failed to send error response: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    public PrivilegesEvaluatorResponse evaluateByRoleName(Map<String, Object> proposedBody, String roleName, boolean hasProposedConfig) throws IOException {
        String action = (String) proposedBody.get(ACTION);
        String index = proposedBody.containsKey(INDEX) ? (String) proposedBody.get(INDEX) : null;
        String id = proposedBody.containsKey(ID) ? (String) proposedBody.get(ID) : null;

        ActionRequest actionRequest = createActionRequest(action, index, id);
        ImmutableSet<String> mappedRoles = ImmutableSet.of(roleName);

        User user=new User("role_simulation");
        Map<String, Object> proposedRoles = (Map<String, Object>) proposedBody.getOrDefault(ROLES, Map.of());
        ActionPrivileges actionPrivileges;

        if (hasProposedConfig && proposedRoles.containsKey(roleName)) {
            Map<String, Object> proposedActionGroups = (Map<String, Object>) proposedBody.getOrDefault(ACTION_GROUPS, Map.of());

            actionPrivileges = createActionPrivileges(
                    proposedRoles,
                    proposedActionGroups,
                    securityApiDependencies.settings()
            );

        } else {
            SecurityDynamicConfiguration<RoleV7> currentRoles = (SecurityDynamicConfiguration<RoleV7>) load(CType.ROLES, false);
            SecurityDynamicConfiguration<ActionGroupsV7> currentActionGroups =  (SecurityDynamicConfiguration<ActionGroupsV7>) load(CType.ACTIONGROUPS, false);
            actionPrivileges =  new RoleBasedActionPrivileges(
                    currentRoles,
                    new FlattenedActionGroups(currentActionGroups),
                    securityApiDependencies.settings()
            );
        }

        PrivilegesEvaluationContext context = new PrivilegesEvaluationContext(
                user,
                mappedRoles,
                action,
                actionRequest,
                null,
                irr,
                indexNameExpressionResolver,
                clusterService::state,
                actionPrivileges
        );

        return securityApiDependencies.privilegesEvaluator().evaluate(context);
    }

    public PrivilegesEvaluatorResponse evaluateWithCurrentConfig(Map<String, Object> proposedBody) {
        String action = (String) proposedBody.get(ACTION);

        ThreadContext threadContext = threadPool.getThreadContext();
        TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);

        String simulatedUserName = (String) proposedBody.get(USER);
        User user = new User(simulatedUserName);

        PrivilegesEvaluationContext cxt = securityApiDependencies.privilegesEvaluator()
                .createContext(user, action);
        ActionPrivileges currentActionPrivileges = cxt.getActionPrivileges();
        ImmutableSet<String> mappedRoles = ImmutableSet.copyOf(
                securityApiDependencies.privilegesEvaluator().mapRoles(user, caller)
        );

        String index = proposedBody.containsKey(INDEX) ? (String) proposedBody.get(INDEX) : null;
        String id = proposedBody.containsKey(ID) ? (String) proposedBody.get(ID) : null;
        ActionRequest actionRequest = createActionRequest(action, index, id);

        PrivilegesEvaluationContext context = new PrivilegesEvaluationContext(
                user,
                mappedRoles,
                action,
                actionRequest,
                null, // task
                irr,
                indexNameExpressionResolver,
                clusterService::state,
                currentActionPrivileges
        );

        log.info("Using current config for user: {} with roles: {}", user.getName(), mappedRoles);
        return securityApiDependencies.privilegesEvaluator().evaluate(context);
    }

    public PrivilegesEvaluatorResponse evaluateWithProposedConfig(Map<String, Object> proposedBody) {

        @SuppressWarnings("unchecked")
        Map<String, Object> proposedRoles = (Map<String, Object>) proposedBody.getOrDefault(ROLES, Map.of());
        @SuppressWarnings("unchecked")
        Map<String, Object> proposedActionGroups = (Map<String, Object>) proposedBody.getOrDefault(ACTION_GROUPS, Map.of());

        try {
            ActionPrivileges actionPrivileges = createActionPrivileges(
                    proposedRoles,
                    proposedActionGroups,
                    securityApiDependencies.settings()
            );

            PrivilegesEvaluationContext context = createPrivilegesEvaluationContext(
                    proposedBody,
                    clusterService,
                    irr,
                    indexNameExpressionResolver,
                    actionPrivileges
            );

            log.info("Using custom simulation config for user: {}", context.getUser().getName());

            return securityApiDependencies.privilegesEvaluator().evaluate(context);

        } catch (IOException e) {
            throw new RuntimeException("Error while simulating permissions using custom configuration: ", e);
        }
    }

    public ActionPrivileges createActionPrivileges(
            Map<String, Object> proposedRoles,
            Map<String, Object> proposedActionGroups,
            Settings settings
    ) throws IOException {

        SecurityDynamicConfiguration<RoleV7> rolesConfig = SecurityDynamicConfiguration.fromMap(proposedRoles, CType.ROLES);

        SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsConfig = SecurityDynamicConfiguration.fromMap(proposedActionGroups, CType.ACTIONGROUPS);
        FlattenedActionGroups flattenedActionGroups = new FlattenedActionGroups(actionGroupsConfig);

        return new RoleBasedActionPrivileges(
                rolesConfig,
                flattenedActionGroups,
                settings
        );
    }

    @SuppressWarnings("unchecked")
    public PrivilegesEvaluationContext createPrivilegesEvaluationContext(
            Map<String, Object> proposedBody,
            ClusterService clusterService,
            IndexResolverReplacer irr,
            IndexNameExpressionResolver indexNameExpressionResolver,
            ActionPrivileges actionPrivileges )
    {
        String action = (String) proposedBody.get(ACTION);
        String index = proposedBody.containsKey(INDEX) ? (String) proposedBody.get(INDEX) : null;
        String id= proposedBody.containsKey(ID) ? (String) proposedBody.get(ID) : null;


        String simulatedUserName = (String) proposedBody.get(USER);
        User user=new User(simulatedUserName);

        Map<String, Object> proposedRoleMappings = (Map<String, Object>) proposedBody.getOrDefault(ROLES_MAPPING, Map.of());
        ImmutableSet<String> mappedRoles = getMappedRolesForUser(user,proposedRoleMappings);

        Supplier<ClusterState> clusterStateSupplier = clusterService::state;
        ActionRequest actionRequest = createActionRequest(action, index, id);

        return new PrivilegesEvaluationContext(
                user,
                mappedRoles,
                action,
                actionRequest,
                null,
                irr,
                indexNameExpressionResolver,
                clusterStateSupplier,
                actionPrivileges
        );
    }
    public ImmutableSet<String> getMappedRolesForUser(User user, Map<String, Object> proposedRoleMappings){
        try {
            SecurityDynamicConfiguration<RoleMappingsV7> rolesMappingConfig = SecurityDynamicConfiguration.fromMap(proposedRoleMappings, CType.ROLESMAPPING);
            ImmutableSet.Builder<String> mappedRolesBuilder = ImmutableSet.builder();

            for (Map.Entry<String, RoleMappingsV7> roleMappingEntry : rolesMappingConfig.getCEntries().entrySet()) {
                String roleName = roleMappingEntry.getKey();
                RoleMappingsV7 roleMapping = roleMappingEntry.getValue();

                if(roleMapping.getUsers()!=null && roleMapping.getUsers().contains(user.getName())){
                    mappedRolesBuilder.add(roleName);
                }
            }
            return  mappedRolesBuilder.build();
        }catch (IOException e){
            throw new RuntimeException("Failed to process role mappings: "+e.getMessage());
        }
    }

    public ActionRequest createActionRequest(String action, String index, String id) {
        switch (action) {

            case "indices:admin/create":
                return new CreateIndexRequest(index);

            case "indices:admin/delete":
                return new DeleteIndexRequest(index);

            // Search-related operations
            case "indices:data/read/search":
                return new SearchRequest(index);

            case "indices:data/read/scroll":
                return new SearchScrollRequest();

            case "indices:data/read/scroll/clear":
                return new ClearScrollRequest();

            // Retrieving  individual or multiple documents
            case "indices:data/read/get":
                if(id==null){
                    return new GetRequest(index);
                }
                return new GetRequest(index, id);

            case "indices:data/read/mget":
                return new MultiGetRequest();


            // Multi-search
            case "indices:data/read/msearch":
                return new MultiSearchRequest();

            // Write operations on documents
            case "indices:data/write/index":
                return new IndexRequest(index);

            case "indices:data/write/update":
                return new UpdateRequest(index,id);

            case "indices:data/write/delete":
                if(id==null){
                    return new DeleteRequest(index);
                }
                return new DeleteRequest(index, id);

            case "indices:data/write/bulk":
                return new BulkRequest();


            // Point-in-time operations
            // case "indices:data/read/point_in_time/create":
            //   return new CreatePitRequest();

            case "indices:data/read/point_in_time/delete":
                return new DeletePitRequest();

            case "indices:data/read/point_in_time/readall":
                return new GetAllPitNodesRequest();


            // Search pipeline operations
            case "cluster:admin/search/pipeline/get":
                return new GetSearchPipelineRequest(index);

            case "cluster:admin/search/pipeline/delete":
                return new DeleteSearchPipelineRequest();

            //cluster health
            case  "cluster:monitor/health":
                return new ClusterHealthRequest();



            case "indices:data/read/explain":
                return new ExplainRequest(index, id);

            case "indices:data/read/field_caps":
                return new  FieldCapabilitiesRequest();


            // Default case for unknown actions
            default:
                return new ActionRequest() {
                    @Override
                    public ActionRequestValidationException validate() {
                        return null;
                    }
                };
        }
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {
            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigLoad(SecurityConfiguration securityConfiguration) {
                return ValidationResult.success(securityConfiguration);
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigDelete(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Delete is not supported on this endpoint"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Changes are not allowed via Impact Analysis API"));
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };

    }
}