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
package org.opensearch.security.privileges.actionlevel.nextgen;

import java.util.Map;
import java.util.function.Supplier;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.IndicesRequest.Replaceable;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.single.shard.SingleShardRequest;
import org.opensearch.action.termvectors.MultiTermVectorsRequest;
import org.opensearch.action.termvectors.TermVectorsRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.privileges.DashboardsMultiTenancyConfiguration;
import org.opensearch.security.privileges.DocumentAllowList;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.TenantPrivileges;
import org.opensearch.security.user.User;
import org.opensearch.transport.client.Client;

/**
 * Formerly known as PrivilegesInterceptor, this handles requests to the OpenSearch Dashboards system indices and
 * adds support for multi tenancy to these.
 */
public class DashboardsMultitenancySystemIndexHandler {
    private static final String USER_TENANT = "__user__";
    private static final Map<String, Object> KIBANA_INDEX_SETTINGS = ImmutableMap.of(
        IndexMetadata.SETTING_NUMBER_OF_SHARDS,
        1,
        IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS,
        "0-1"
    );

    private static final ImmutableSet<String> READ_ONLY_ALLOWED_ACTIONS = ImmutableSet.of(
        "indices:admin/get",
        "indices:data/read/get",
        "indices:data/read/search",
        "indices:data/read/msearch",
        "indices:data/read/mget",
        "indices:data/read/mget[shard]"
    );

    private static final Logger log = LogManager.getLogger(DashboardsMultitenancySystemIndexHandler.class);

    private final Supplier<TenantPrivileges> tenantPrivilegesSupplier;
    private final Supplier<DashboardsMultiTenancyConfiguration> multiTenancyConfigurationSupplier;
    private final Supplier<ClusterState> clusterStateSupplier;
    private final ThreadContext threadContext;
    private final Client client;

    public DashboardsMultitenancySystemIndexHandler(
        Supplier<ClusterState> clusterStateSupplier,
        Client client,
        ThreadContext threadContext,
        Supplier<TenantPrivileges> tenantPrivilegesSupplier,
        Supplier<DashboardsMultiTenancyConfiguration> multiTenancyConfigurationSupplier
    ) {
        this.tenantPrivilegesSupplier = tenantPrivilegesSupplier;
        this.multiTenancyConfigurationSupplier = multiTenancyConfigurationSupplier;
        this.clusterStateSupplier = clusterStateSupplier;
        this.threadContext = threadContext;
        this.client = client;
    }

    /**
     * @return A PrivilegeEvaluatorResponse if the request handling has been finished inside this method. Returns
     * null if this method did not handle it and evaluation should continue as normal.
     */
    public PrivilegesEvaluatorResponse handle(
        final ActionRequest request,
        final String action,
        final User user,
        final PrivilegesEvaluationContext context
    ) {
        DashboardsMultiTenancyConfiguration config = this.multiTenancyConfigurationSupplier.get();

        if (!config.multitenancyEnabled()) {
            return null;
        }

        if (user.getName().equals(config.dashboardsServerUsername())) {
            // For the OpenSearch Dashboards system user, we do not apply multi-tenancy handling
            // The normal index privileges defined in static_roles.yml will apply
            return null;
        }

        String dashboardsAliasName = config.dashboardsIndex();
        if (dashboardsAliasName == null) {
            log.error("Dashboards index is not configured, cannot apply multi-tenancy handling");
            return null;
        }

        OptionallyResolvedIndices optionallyResolvedIndices = context.getResolvedIndices();
        if (!(optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices)) {
            // If we have no information about the indices, it is safe to skip multi tenancy handling
            return null;
        }

        if (resolvedIndices.local().names().size() != 1 || !resolvedIndices.remote().isEmpty()) {
            // This handler only applies for requests operating on exactly one index or alias (we expect the Dashboards
            // index or alias)
            return null;
        }

        if (USER_TENANT.equals(user.getRequestedTenant())) {
            if (!config.privateTenantEnabled()) {
                return PrivilegesEvaluatorResponse.insufficient(action)
                    .reason("Dashboards Multitenancy: The private tenant feature is disabled.");
            }
        }

        String referencedIndexOrAlias = resolvedIndices.local().names().iterator().next();

        if (dashboardsAliasName.equals(referencedIndexOrAlias)) {
            // This is a request to the plain top-level .kibana index.
            // We check permissions and - if this is not the global tenant - rewrite to the requested tenant index
            log.debug(
                "Handling Dashboards MT: top-level alias {} requested; requested tenant: {}",
                referencedIndexOrAlias,
                user.getRequestedTenant()
            );
            if (hasPermission(context)) {
                if (isGlobalTenant(context.getUser().getRequestedTenant())) {
                    applyDocumentAllowList(dashboardsAliasName);
                    return PrivilegesEvaluatorResponse.ok();
                } else {
                    String tenantAliasName = tenantAliasName(user, dashboardsAliasName);
                    applyDocumentAllowList(tenantAliasName);
                    return replaceIndex(context, request, referencedIndexOrAlias, tenantAliasName);
                }
            } else {
                return PrivilegesEvaluatorResponse.insufficient(action)
                    .reason("Dashboards Multitenancy: Insufficient privileges for tenant.");
            }
        } else if (referencedIndexOrAlias.startsWith(dashboardsAliasName)) {
            // This is a request to either:
            // - .kibana_001: A backing index of the top-level .kibana alias
            // - .kibana_1592542611_tenantname: A rewritten tenant alias
            // - .kibana_1592542611_tenantname_001: A backing index of a rewritten tenant alias
            // We check permission and validate that the index name matches the expectation given the requested tenant.
            // We do not need to rewrite, as this should have happened in the action that triggered this sub-request.
            log.debug(
                "Handling Dashboards MT: non-top-level index/alias {} requested; requested tenant: {}",
                referencedIndexOrAlias,
                user.getRequestedTenant()
            );
            if (hasPermission(context)) {
                String tenantAliasName = tenantAliasName(user, dashboardsAliasName);
                if (referencedIndexOrAlias.equals(tenantAliasName)) {
                    applyDocumentAllowList(tenantAliasName);
                    return PrivilegesEvaluatorResponse.ok();
                } else if (referencedIndexOrAlias.startsWith(tenantAliasName)) {
                    if (isGlobalTenant(context)) {
                        String aliasOfIndex = aliasOfIndex(referencedIndexOrAlias, dashboardsAliasName);
                        if (aliasOfIndex != null && aliasOfIndex.equals(dashboardsAliasName)) {
                            // This is a backing index of the top-level .kibana alias
                            applyDocumentAllowList(dashboardsAliasName);
                            return PrivilegesEvaluatorResponse.ok();
                        } else {
                            return PrivilegesEvaluatorResponse.insufficient(action)
                                .reason("Dashboards Multitenancy: Referenced index does not match requested tenant (global tenant)");
                        }
                    } else {
                        // This is a tenant with an alias like .kibana_1592542611_tenantname
                        // The startsWith check done before is sufficient here to check ownership
                        applyDocumentAllowList(tenantAliasName);
                        return PrivilegesEvaluatorResponse.ok();
                    }
                } else {
                    return PrivilegesEvaluatorResponse.insufficient(action)
                        .reason("Dashboards Multitenancy: Referenced index does not match requested tenant.");
                }
            } else {
                return PrivilegesEvaluatorResponse.insufficient(action)
                    .reason("Dashboards Multitenancy: Insufficient privileges for tenant.");
            }
        } else {
            // Does not reference the dashboards alias or any of its tenant indices
            return null;
        }
    }

    private boolean hasPermission(PrivilegesEvaluationContext context) {
        String tenant = context.getUser().getRequestedTenant();

        if (isGlobalTenant(tenant)) {
            return this.tenantPrivilegesSupplier.get()
                .hasTenantPrivilege(context, "global_tenant", getActionTypeForAction(context.getAction()));
        } else if (USER_TENANT.equals(tenant)) {
            return true;
        } else {
            return this.tenantPrivilegesSupplier.get().hasTenantPrivilege(context, tenant, getActionTypeForAction(context.getAction()));
        }
    }

    private void applyDocumentAllowList(String indexName) {
        DocumentAllowList documentAllowList = new DocumentAllowList();
        documentAllowList.add(indexName, "*");
        IndexAbstraction indexAbstraction = this.clusterStateSupplier.get().getMetadata().getIndicesLookup().get(indexName);

        if (indexAbstraction instanceof IndexAbstraction.Alias) {
            for (IndexMetadata index : indexAbstraction.getIndices()) {
                documentAllowList.add(index.getIndex().getName(), "*");
            }
        }

        documentAllowList.applyTo(this.threadContext);
    }

    static TenantPrivileges.ActionType getActionTypeForAction(String action) {
        if (READ_ONLY_ALLOWED_ACTIONS.contains(action)) {
            return TenantPrivileges.ActionType.READ;
        } else {
            return TenantPrivileges.ActionType.WRITE;
        }
    }

    private String getConcreteIndexName(String name, Map<String, IndexAbstraction> indicesLookup) {
        for (int i = 1; i < Integer.MAX_VALUE; i++) {
            String concreteName = name.concat("_" + i);
            if (indicesLookup.get(concreteName) == null) {
                return concreteName;
            }
        }
        log.warn("Can not find a suitable name for multi-tenant index {}", name);
        return null;

    }

    private boolean indexExists(String name) {
        Map<String, IndexAbstraction> indicesLookup = this.clusterStateSupplier.get().getMetadata().getIndicesLookup();
        IndexAbstraction indexAbstraction = indicesLookup.get(name);
        if (indexAbstraction != null) {
            if (indexAbstraction.getType() == IndexAbstraction.Type.ALIAS) {
                log.debug("Alias {} already exists", name);
            } else {
                log.warn("Can not create kibana multi-tenant alias {} as an index with the same name already exists", name);
            }
            return true;
        } else {
            return false;
        }
    }

    private CreateIndexRequestBuilder newCreateIndexRequestBuilder(final String name) {
        Map<String, IndexAbstraction> indicesLookup = this.clusterStateSupplier.get().getMetadata().getIndicesLookup();
        String concreteName = getConcreteIndexName(name, indicesLookup);
        if (concreteName != null) {
            return client.admin()
                .indices()
                .prepareCreate(concreteName)
                .addAlias(new Alias(name))
                .setSettings(KIBANA_INDEX_SETTINGS)
                .setCause("auto(multi-tenant)");
        }
        return null;
    }

    private PrivilegesEvaluatorResponse replaceIndex(
        PrivilegesEvaluationContext context,
        ActionRequest request,
        String oldIndexName,
        String newIndexName
    ) {
        log.debug("{} index will be replaced with {} in {}", oldIndexName, newIndexName, request);

        String[] newIndexNames = new String[] { newIndexName };

        if (request instanceof CreateIndexRequest) {
            String concreteName = getConcreteIndexName(newIndexName, clusterStateSupplier.get().getMetadata().getIndicesLookup());
            if (concreteName != null) {
                // use new name for alias and suffixed index name
                ((CreateIndexRequest) request).index(concreteName).alias(new Alias(newIndexName));
            } else {
                ((CreateIndexRequest) request).index(newIndexName);
            }
        } else if (request instanceof BulkRequest bulkRequest) {
            for (DocWriteRequest<?> ar : bulkRequest.requests()) {

                if (ar instanceof DeleteRequest) {
                    ((DeleteRequest) ar).index(newIndexName);
                }

                if (ar instanceof IndexRequest) {
                    ((IndexRequest) ar).index(newIndexName);
                }

                if (ar instanceof UpdateRequest) {
                    ((UpdateRequest) ar).index(newIndexName);
                }
            }

            // Please see comment for DeleteRequest below. Multi-tenant index may be auto created for any type of
            // DocWriteRequest
            if (!bulkRequest.requests().isEmpty()) {
                if (!indexExists(newIndexName)) {
                    return PrivilegesEvaluatorResponse.ok().with(newCreateIndexRequestBuilder(newIndexName));
                }
            }
        } else if (request instanceof MultiGetRequest multiGetRequest) {
            for (MultiGetRequest.Item item : multiGetRequest.getItems()) {
                item.index(newIndexName);
            }
        } else if (request instanceof MultiTermVectorsRequest multiTermVectorsRequest) {
            for (TermVectorsRequest termVectorsRequest : multiTermVectorsRequest.getRequests()) {
                termVectorsRequest.index(newIndexName);
            }
        } else if (request instanceof DocWriteRequest<?> indexRequest) {
            indexRequest.index(newIndexName);
            if (!indexExists(newIndexName)) {
                return PrivilegesEvaluatorResponse.ok().with(newCreateIndexRequestBuilder(newIndexName));
            }
        } else if (request instanceof SingleShardRequest<?> singleShardRequest) {
            singleShardRequest.index(newIndexName);
        } else if (request instanceof RefreshRequest refreshRequest) {
            refreshRequest.indices(newIndexNames);
        } else if (request instanceof Replaceable replaceableRequest) {
            replaceableRequest.indices(newIndexNames);
        } else {
            log.warn("Unhandled request {}", request.getClass());
            return PrivilegesEvaluatorResponse.insufficient(context.getAction())
                .reason("Request is not supported by OpenSearch Dashboards multitenancy handler.");
        }

        return PrivilegesEvaluatorResponse.ok();
    }

    String aliasOfIndex(String indexName, String configuredDashboardsIndex) {
        IndexMetadata indexMetadata = this.clusterStateSupplier.get().getMetadata().index(indexName);
        if (indexMetadata != null) {
            for (String alias : indexMetadata.getAliases().keySet()) {
                if (alias.startsWith(configuredDashboardsIndex)) {
                    return alias;
                }
            }
        }

        return null;
    }

    private String tenantAliasName(User user, String baseIndexName) {
        String tenant = user.getRequestedTenant();

        if (isGlobalTenant(tenant)) {
            return baseIndexName;
        } else if (USER_TENANT.equals(tenant)) {
            tenant = user.getName();
        }

        return baseIndexName + "_" + tenant.hashCode() + "_" + tenant.toLowerCase().replaceAll("[^a-z0-9]+", "");
    }

    private static boolean isGlobalTenant(PrivilegesEvaluationContext context) {
        return isGlobalTenant(context.getUser().getRequestedTenant());
    }

    private static boolean isGlobalTenant(String tenant) {
        return tenant == null || tenant.isEmpty();
    }
}
