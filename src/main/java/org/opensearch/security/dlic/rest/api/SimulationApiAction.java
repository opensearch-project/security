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
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
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

public class SimulationApiAction extends AbstractApiAction {

    private static final List<Route> routes = addRoutesPrefix(List.of(
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

    public SimulationApiAction(ClusterService clusterService, ThreadPool threadPool, SecurityApiDependencies securityApiDependencies, IndexResolverReplacer irr,
                               IndexNameExpressionResolver indexNameExpressionResolver)  {
        super(Endpoint.SIMULATION, clusterService, threadPool, securityApiDependencies);
        this.irr = irr;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.requestHandlersBuilder.add(RestRequest.Method.POST, this::handleSimulationRequest).withAccessHandler(request -> true);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType<?> getConfigType() {
        return null;
    }

    private void handleSimulationRequest(RestChannel channel, RestRequest request, Client client){
        try {

            Map<String, Object> proposedBody = DefaultObjectMapper.objectMapper.readValue(
                    request.content().utf8ToString(),
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
                    }
            );

            Boolean usingCurrentConfig = (Boolean) proposedBody.get("using_current_config");
            PrivilegesEvaluatorResponse response;

            if (Boolean.TRUE.equals(usingCurrentConfig)) {
                response = evaluateWithCurrentConfig(proposedBody);
            } else {
                response = evaluateWithProposedConfig(proposedBody);
            }

            // Build response
            XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            builder.field("accessAllowed", response.isAllowed());
            builder.field("missingPrivileges", response.getMissingPrivileges());
            builder.endObject();

            channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));

        } catch (Exception e) {
            internalServerError(channel, "Error simulating permissions: " + e.getMessage());
        }

    }

    private PrivilegesEvaluatorResponse evaluateWithCurrentConfig(Map<String, Object> proposedBody) {
        String action = (String) proposedBody.get(ACTION);

        ThreadContext threadContext = threadPool.getThreadContext();
        TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);

        User user;
        String simulatedUserName = (String) proposedBody.get("user");
        if (simulatedUserName != null && !simulatedUserName.isEmpty()) {
            user = new User(simulatedUserName);
        } else {
            user = getAuthenticatedUser(threadContext);
        }

        PrivilegesEvaluationContext cxt = securityApiDependencies.privilegesEvaluator()
                .createContext(user, action);
        ActionPrivileges currentActionPrivileges = cxt.getActionPrivileges();

        Set<String> currentMappedRoles = securityApiDependencies.privilegesEvaluator().mapRoles(user, caller);
        ImmutableSet<String> mappedRoles = ImmutableSet.copyOf(currentMappedRoles);

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

        log.info("Using current cluster config for user: {} with roles: {}", user.getName(), mappedRoles);
        return securityApiDependencies.privilegesEvaluator().evaluate(context);
    }

    private PrivilegesEvaluatorResponse evaluateWithProposedConfig(Map<String, Object> proposedBody) {

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
                    threadPool,
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

    private ActionPrivileges createActionPrivileges(
            Map<String, Object> proposedRoles,
            Map<String, Object> proposedActionGroups,
            Settings settings
    ) throws IOException {

        SecurityDynamicConfiguration<RoleV7> rolesConfig = SecurityDynamicConfiguration.fromMap(proposedRoles, CType.ROLES);

        SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsConfig = SecurityDynamicConfiguration.fromMap(proposedActionGroups, CType.ACTIONGROUPS);
        FlattenedActionGroups flattenedActionGroups = new FlattenedActionGroups(actionGroupsConfig.withStaticConfig());

        return new RoleBasedActionPrivileges(
                rolesConfig.withStaticConfig(),
                flattenedActionGroups,
                settings
        );
    }

    @SuppressWarnings("unchecked")
    private PrivilegesEvaluationContext createPrivilegesEvaluationContext(
            Map<String, Object> proposedBody,
            ThreadPool threadPool,
            ClusterService clusterService,
            IndexResolverReplacer irr,
            IndexNameExpressionResolver indexNameExpressionResolver,
            ActionPrivileges actionPrivileges )
    {
        ThreadContext threadContext = threadPool.getThreadContext();
        String action = (String) proposedBody.get(ACTION);
        if (action == null || action.isEmpty()) {
            throw new IllegalArgumentException("Missing action in request body");
        }

        String index = proposedBody.containsKey(INDEX) ? (String) proposedBody.get(INDEX) : null;

        String id= proposedBody.containsKey(ID) ? (String) proposedBody.get(ID) : null;

        User user;
        String simulatedUserName = (String) proposedBody.get("user");
        if (simulatedUserName != null && !simulatedUserName.isEmpty()) {
            user = new User(simulatedUserName);
            log.info("Using simulated user: {}", simulatedUserName);
        } else {
            user = getAuthenticatedUser(threadContext);
            log.info("Using authenticated user: {}", user.getName());
        }

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

    @SuppressWarnings("unchecked")
    private ImmutableSet<String> getMappedRolesForUser(User user, Map<String, Object> proposedRoleMappings) {
        Set<String> mappedRoles = new HashSet<>();

        for (Map.Entry<String, Object> roleMappingEntry : proposedRoleMappings.entrySet()) {
            String roleName = roleMappingEntry.getKey();
            Map<String, Object> roleMapping = (Map<String, Object>) roleMappingEntry.getValue();

            List<String> users = (List<String>) roleMapping.getOrDefault("users", List.of());
            if (users.contains(user.getName())) {
                mappedRoles.add(roleName);
            }
        }

        return ImmutableSet.copyOf(mappedRoles);
    }

    private ActionRequest createActionRequest(String action, String index, String id) {
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
                return new GetRequest(index, "1");

            case "indices:data/read/mget":
                return new MultiGetRequest();


            // Multi-search
            case "indices:data/read/msearch":
                return new MultiSearchRequest();

            // Write operations on documents
            case "indices:data/write/index":
                return new IndexRequest(index);

            case "indices:data/write/update":
                return new UpdateRequest(index,"1");

            case "indices:data/write/delete":
                return new DeleteRequest(index, "1");

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
                return new ExplainRequest(index, "1");

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

    private User getAuthenticatedUser(ThreadContext threadContext) {
        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null) {
            throw new OpenSearchSecurityException("User is not authenticated.");
        }
        return user;
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