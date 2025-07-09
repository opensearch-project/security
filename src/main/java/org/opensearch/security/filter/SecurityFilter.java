/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.filter;

import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocWriteRequest.OpType;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.close.CloseIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.logging.LoggerMessageFormat;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.index.reindex.UpdateByQueryRequest;
import org.opensearch.security.action.simulate.PermissionCheckResponse;
import org.opensearch.security.action.whoami.WhoAmIAction;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auth.RolesInjector;
import org.opensearch.security.auth.UserInjector;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.configuration.DlsFlsRequestValve;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.ResourceAccessEvaluator;
import org.opensearch.security.privileges.RoleMapper;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.support.SourceFieldsContext;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.ThreadContextUserInfo;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.OpenSearchSecurityPlugin.isActionTraceEnabled;
import static org.opensearch.security.OpenSearchSecurityPlugin.traceAction;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PERFORM_PERMISSION_CHECK_PARAM;

public class SecurityFilter implements ActionFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesConfiguration privilegesConfiguration;
    private final RoleMapper roleMapper;
    private final AdminDNs adminDns;
    private final DlsFlsRequestValve dlsFlsValve;
    private final AuditLog auditLog;
    private final ThreadPool threadPool;
    private final ClusterService cs;
    private final ClusterInfoHolder clusterInfoHolder;
    private final CompatConfig compatConfig;
    private final XFFResolver xffResolver;
    private final WildcardMatcher immutableIndicesMatcher;
    private final RolesInjector rolesInjector;
    private final UserInjector userInjector;
    private final ResourceAccessEvaluator resourceAccessEvaluator;
    private final ThreadContextUserInfo threadContextUserInfo;

    public SecurityFilter(
        final Settings settings,
        PrivilegesConfiguration privilegesConfiguration,
        RoleMapper roleMapper,
        final AdminDNs adminDns,
        DlsFlsRequestValve dlsFlsValve,
        AuditLog auditLog,
        ThreadPool threadPool,
        ClusterService cs,
        final ClusterInfoHolder clusterInfoHolder,
        final CompatConfig compatConfig,
        final XFFResolver xffResolver,
        ResourceAccessEvaluator resourceAccessEvaluator
    ) {
        this.privilegesConfiguration = privilegesConfiguration;
        this.roleMapper = roleMapper;
        this.adminDns = adminDns;
        this.dlsFlsValve = dlsFlsValve;
        this.auditLog = auditLog;
        this.threadPool = threadPool;
        this.cs = cs;
        this.clusterInfoHolder = clusterInfoHolder;
        this.compatConfig = compatConfig;
        this.xffResolver = xffResolver;
        this.immutableIndicesMatcher = WildcardMatcher.from(
            settings.getAsList(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList())
        );
        this.rolesInjector = new RolesInjector(auditLog);
        this.userInjector = new UserInjector(settings, threadPool, auditLog, xffResolver);
        this.resourceAccessEvaluator = new ResourceAccessEvaluator(resourceIndices, settings, resourceAccessHandler);
        this.threadContextUserInfo = new ThreadContextUserInfo(threadPool.getThreadContext(), privilegesConfiguration, settings);
        log.info("{} indices are made immutable.", immutableIndicesMatcher);
    }

    @VisibleForTesting
    WildcardMatcher getImmutableIndicesMatcher() {
        return immutableIndicesMatcher;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(
        Task task,
        final String action,
        Request request,
        ActionRequestMetadata<Request, Response> actionRequestMetadata,
        ActionListener<Response> listener,
        ActionFilterChain<Request, Response> chain
    ) {
        try (StoredContext ctx = threadPool.getThreadContext().newStoredContext(true)) {
            org.apache.logging.log4j.ThreadContext.clearAll();
            apply0(task, action, request, actionRequestMetadata, listener, chain);
        }
    }

    private static Set<String> alias2Name(Set<Alias> aliases) {
        return aliases.stream().map(a -> a.name()).collect(ImmutableSet.toImmutableSet());
    }

    private <Request extends ActionRequest, Response extends ActionResponse> void apply0(
        Task task,
        final String action,
        Request request,
        ActionRequestMetadata<Request, Response> actionRequestMetadata,
        ActionListener<Response> listener,
        ActionFilterChain<Request, Response> chain
    ) {
        try {
            ThreadContext threadContext = threadPool.getThreadContext();
            if (threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN) == null) {
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.LOCAL.toString());
            }

            final ComplianceConfig complianceConfig = auditLog.getComplianceConfig();
            if (complianceConfig != null && complianceConfig.isEnabled()) {
                attachSourceFieldContext(request);
            }
            rolesInjector.injectUserAndRoles(threadPool);
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            if (user == null) {
                UserInjector.Result injectedUser = userInjector.getInjectedUser();
                if (injectedUser != null) {
                    user = injectedUser.getUser();
                    threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
                }
            }
            if (user != null && threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER) == null) {
                threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, new UserSubjectImpl(threadPool, user));
            }
            final boolean userIsAdmin = isUserAdmin(user, adminDns);
            final boolean interClusterRequest = HeaderHelper.isInterClusterRequest(threadContext);
            final boolean trustedClusterRequest = HeaderHelper.isTrustedClusterRequest(threadContext);
            final boolean confRequest = "true".equals(
                HeaderHelper.getSafeFromHeader(threadContext, ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER)
            );
            final boolean passThroughRequest = action.startsWith("indices:admin/seq_no") || action.equals(WhoAmIAction.NAME);

            final boolean internalRequest = (interClusterRequest || HeaderHelper.isDirectRequest(threadContext))
                && action.startsWith("internal:")
                && !action.startsWith("internal:transport/proxy");

            if (user != null) {
                org.apache.logging.log4j.ThreadContext.put("user", user.getName());
            }

            if (isActionTraceEnabled()) {

                String count = "";
                if (request instanceof BulkRequest) {
                    count = "" + ((BulkRequest) request).requests().size();
                }

                if (request instanceof MultiGetRequest) {
                    count = "" + ((MultiGetRequest) request).getItems().size();
                }

                if (request instanceof MultiSearchRequest) {
                    count = "" + ((MultiSearchRequest) request).requests().size();
                }

                traceAction(
                    "Node "
                        + cs.localNode().getName()
                        + " -> "
                        + action
                        + " ("
                        + count
                        + "): userIsAdmin="
                        + userIsAdmin
                        + "/conRequest="
                        + confRequest
                        + "/internalRequest="
                        + internalRequest
                        + "origin="
                        + threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN)
                        + "/directRequest="
                        + HeaderHelper.isDirectRequest(threadContext)
                        + "/remoteAddress="
                        + request.remoteAddress()
                );

                threadContext.putHeader(
                    "_opendistro_security_trace" + System.currentTimeMillis() + "#" + UUID.randomUUID().toString(),
                    Thread.currentThread().getName()
                        + " FILTER -> "
                        + "Node "
                        + cs.localNode().getName()
                        + " -> "
                        + action
                        + " userIsAdmin="
                        + userIsAdmin
                        + "/conRequest="
                        + confRequest
                        + "/internalRequest="
                        + internalRequest
                        + "origin="
                        + threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN)
                        + "/directRequest="
                        + HeaderHelper.isDirectRequest(threadContext)
                        + "/remoteAddress="
                        + request.remoteAddress()
                        + " "
                        + threadContext.getHeaders()
                            .entrySet()
                            .stream()
                            .filter(p -> !p.getKey().startsWith("_opendistro_security_trace"))
                            .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()))
                );

            }

            if (userIsAdmin || confRequest || internalRequest || passThroughRequest) {

                if (userIsAdmin && !confRequest && !internalRequest && !passThroughRequest) {
                    auditLog.logGrantedPrivileges(action, request, task);
                    auditLog.logIndexEvent(action, request, task);
                }

                chain.proceed(task, action, request, listener);
                return;
            }

            if (immutableIndicesMatcher != WildcardMatcher.NONE) {

                boolean isImmutable = false;

                if (request instanceof BulkShardRequest) {
                    for (BulkItemRequest bsr : ((BulkShardRequest) request).items()) {
                        isImmutable = checkImmutableIndices(bsr.request(), actionRequestMetadata, listener);
                        if (isImmutable) {
                            break;
                        }
                    }
                } else {
                    isImmutable = checkImmutableIndices(request, actionRequestMetadata, listener);
                }

                if (isImmutable) {
                    return;
                }

            }

            if (Origin.LOCAL.toString().equals(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN))
                && (interClusterRequest || HeaderHelper.isDirectRequest(threadContext))
                && (user == null)) {

                chain.proceed(task, action, request, listener);
                return;
            }

            if (user == null) {

                if (action.startsWith("cluster:monitor/state")) {
                    chain.proceed(task, action, request, listener);
                    return;
                }

                boolean skipSecurityIfDualMode = threadContext.getTransient(
                    ConfigConstants.SECURITY_SSL_DUAL_MODE_SKIP_SECURITY
                ) == Boolean.TRUE;
                if ((interClusterRequest || trustedClusterRequest || request.remoteAddress() == null)
                    && !compatConfig.transportInterClusterAuthEnabled()) {
                    chain.proceed(task, action, request, listener);
                    return;
                } else if ((interClusterRequest || trustedClusterRequest || request.remoteAddress() == null || skipSecurityIfDualMode)
                    && compatConfig.transportInterClusterPassiveAuthEnabled()) {
                        log.info("Transport auth in passive mode and no user found. Injecting default user");
                        user = User.DEFAULT_TRANSPORT_USER;
                        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
                        if (threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER) == null) {
                            threadContext.putPersistent(
                                ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER,
                                new UserSubjectImpl(threadPool, user)
                            );
                        }
                    } else {
                        log.error(
                            "No user found for "
                                + action
                                + " from "
                                + request.remoteAddress()
                                + " "
                                + threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN)
                                + " via "
                                + threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_CHANNEL_TYPE)
                                + " "
                                + threadContext.getHeaders()
                        );
                        listener.onFailure(
                            new OpenSearchSecurityException("No user found for " + action, RestStatus.INTERNAL_SERVER_ERROR)
                        );
                        return;
                    }
            }

            final PrivilegesEvaluator eval = this.privilegesConfiguration.privilegesEvaluator();

            if (log.isTraceEnabled()) {
                log.trace("Evaluate permissions for user: {}", user.getName());
            }

            PrivilegesEvaluationContext context = eval.createContext(user, action, request, actionRequestMetadata, task);
            this.threadContextUserInfo.setUserInfoInThreadContext(context);
            User finalUser = user;
            Consumer<PrivilegesEvaluatorResponse> handleUnauthorized = response -> {
                auditLog.logMissingPrivileges(action, request, task);
                String err;
                if (!response.getMissingSecurityRoles().isEmpty()) {
                    err = String.format("No mapping for %s on roles %s", finalUser, response.getMissingSecurityRoles());
                } else {
                    err = String.format("no permissions for %s and %s", response.getMissingPrivileges(), finalUser);
                }
                log.debug(err);
                listener.onFailure(new OpenSearchSecurityException(err, RestStatus.FORBIDDEN));
            };

            // NOTE: Since resource-access evaluation requires fetching documents from index, we make the call async otherwise it would
            // require blocking transport threads leading to thread exhaustion and request timeouts
            // We perform the rest of the evaluation as normal if the request is not for resource-access or if the feature is disabled
            if (resourceAccessEvaluator.shouldEvaluate(request)) {
                resourceAccessEvaluator.evaluateAsync(request, action, ActionListener.wrap(response -> {
                    if (handlePermissionCheckRequest(listener, response, action)) {
                        return;
                    }
                    if (response.isAllowed()) {
                        auditLog.logGrantedPrivileges(action, request, task);
                        auditLog.logIndexEvent(action, request, task);
                        chain.proceed(task, action, request, listener);
                    } else {
                        handleUnauthorized.accept(response);
                    }
                }, listener::onFailure));
                // We early return here to skip calling rest of the evaluation as this is a resource-access request
                // Chain will proceed inside the async ActionListener above, if allowed, else returns forbidden
                return;
            }

            // not a resource‐sharing request → fall back into the normal PrivilegesEvaluator
            PrivilegesEvaluatorResponse pres = eval.evaluate(context);

            if (log.isDebugEnabled()) {
                log.debug(pres.toString());
            }
            if (handlePermissionCheckRequest(listener, pres, action)) {
                return;
            }

            if (pres.isAllowed()) {
                auditLog.logGrantedPrivileges(action, request, task);
                auditLog.logIndexEvent(action, request, task);
                if (!dlsFlsValve.invoke(context, listener)) {
                    return;
                }
                final CreateIndexRequestBuilder createIndexRequestBuilder = pres.getCreateIndexRequestBuilder();
                if (createIndexRequestBuilder == null) {
                    chain.proceed(task, action, request, listener);
                } else {
                    CreateIndexRequest createIndexRequest = createIndexRequestBuilder.request();
                    log.info(
                        "Request {} requires new tenant index {} with aliases {}",
                        request.getClass().getSimpleName(),
                        createIndexRequest.index(),
                        alias2Name(createIndexRequest.aliases())
                    );
                    createIndexRequestBuilder.execute(ActionListener.wrap(createIndexResponse -> {
                        if (createIndexResponse.isAcknowledged()) {
                            log.debug(
                                "Request to create index {} with aliases {} acknowledged, proceeding with {}",
                                createIndexRequest.index(),
                                alias2Name(createIndexRequest.aliases()),
                                request.getClass().getSimpleName()
                            );
                            chain.proceed(task, action, request, listener);
                        } else {
                            String message = LoggerMessageFormat.format(
                                "Request to create index {} with aliases {} was not acknowledged, failing {}",
                                createIndexRequest.index(),
                                alias2Name(createIndexRequest.aliases()),
                                request.getClass().getSimpleName()
                            );
                            log.error(message);
                            listener.onFailure(new OpenSearchException(message));
                        }
                    }, e -> {
                        Throwable cause = ExceptionsHelper.unwrapCause(e);
                        if (cause instanceof ResourceAlreadyExistsException) {
                            log.warn(
                                "Request to create index {} with aliases {} failed as the resource already exists, proceeding with {}",
                                createIndexRequest.index(),
                                alias2Name(createIndexRequest.aliases()),
                                request.getClass().getSimpleName(),
                                e
                            );
                            chain.proceed(task, action, request, listener);
                        } else {
                            log.error(
                                "Request to create index {} with aliases {} failed, failing {}",
                                createIndexRequest.index(),
                                alias2Name(createIndexRequest.aliases()),
                                request.getClass().getSimpleName(),
                                e
                            );
                            listener.onFailure(e);
                        }
                    }));
                }
            } else {
                handleUnauthorized.accept(pres);
            }
        } catch (OpenSearchException e) {
            if (task != null) {
                log.debug("Failed to apply filter. Task id: {} ({}). Action: {}", task.getId(), task.getDescription(), action, e);
            } else {
                log.debug("Failed to apply filter. Action: {}", action, e);
            }
            listener.onFailure(e);
        } catch (Throwable e) {
            log.error("Unexpected exception {}", e, e);
            listener.onFailure(new OpenSearchSecurityException("Unexpected exception " + action, RestStatus.INTERNAL_SERVER_ERROR));
        }
    }

    private static boolean isUserAdmin(User user, final AdminDNs adminDns) {
        return user != null && adminDns.isAdmin(user);
    }

    private void attachSourceFieldContext(ActionRequest request) {
        final ThreadContext threadContext = threadPool.getThreadContext();
        if (request instanceof SearchRequest && SourceFieldsContext.isNeeded((SearchRequest) request)) {
            if (threadContext.getHeader("_opendistro_security_source_field_context") == null) {
                final String serializedSourceFieldContext = Base64Helper.serializeObject(new SourceFieldsContext((SearchRequest) request));
                threadContext.putHeader("_opendistro_security_source_field_context", serializedSourceFieldContext);
            }
        } else if (request instanceof GetRequest && SourceFieldsContext.isNeeded((GetRequest) request)) {
            if (threadContext.getHeader("_opendistro_security_source_field_context") == null) {
                final String serializedSourceFieldContext = Base64Helper.serializeObject(new SourceFieldsContext((GetRequest) request));
                threadContext.putHeader("_opendistro_security_source_field_context", serializedSourceFieldContext);
            }
        }
    }

    private <Response extends ActionResponse> boolean handlePermissionCheckRequest(
        ActionListener<Response> listener,
        PrivilegesEvaluatorResponse pres,
        String action
    ) {
        boolean isDryRun = Boolean.parseBoolean(threadPool.getThreadContext().getHeader(SECURITY_PERFORM_PERMISSION_CHECK_PARAM));
        if (!isDryRun) {
            return false;
        }

        @SuppressWarnings("unchecked")
        Response response = (Response) new PermissionCheckResponse(pres.isAllowed(), pres.getMissingPrivileges());
        listener.onResponse(response);

        log.debug(
            "Dry run permission check for action '{}': accessAllowed={}, missingPrivileges={}",
            action,
            pres.isAllowed(),
            pres.getMissingPrivileges()
        );

        return true;
    }

    @SuppressWarnings("rawtypes")
    private boolean checkImmutableIndices(Object request, ActionRequestMetadata<?, ?> actionRequestMetadata, ActionListener listener) {
        final boolean isModifyIndexRequest = request instanceof DeleteRequest
            || request instanceof UpdateRequest
            || request instanceof UpdateByQueryRequest
            || request instanceof DeleteByQueryRequest
            || request instanceof DeleteIndexRequest
            || request instanceof RestoreSnapshotRequest
            || request instanceof CloseIndexRequest
            || request instanceof IndicesAliasesRequest;

        if (isModifyIndexRequest && isRequestIndexImmutable(request, actionRequestMetadata)) {
            listener.onFailure(new OpenSearchSecurityException("Index is immutable", RestStatus.FORBIDDEN));
            return true;
        }

        if ((request instanceof IndexRequest) && isRequestIndexImmutable(request, actionRequestMetadata)) {
            ((IndexRequest) request).opType(OpType.CREATE);
        }

        return false;
    }

    private boolean isRequestIndexImmutable(Object request, ActionRequestMetadata<?, ?> actionRequestMetadata) {
        OptionallyResolvedIndices optionalResolvedIndices = actionRequestMetadata.resolvedIndices();
        if (optionalResolvedIndices instanceof ResolvedIndices resolvedIndices) {
            return immutableIndicesMatcher.matchAny(resolvedIndices.local().namesOfIndices(cs.state()));
        } else {
            return true;
        }
    }
}
