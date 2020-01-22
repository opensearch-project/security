/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.configuration;

import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.IndicesRequest.Replaceable;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsIndexRequest;
import org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsRequest;
import org.elasticsearch.action.admin.indices.refresh.RefreshRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetRequest.Item;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.replication.ReplicationRequest;
import org.elasticsearch.action.support.single.shard.SingleShardRequest;
import org.elasticsearch.action.termvectors.MultiTermVectorsRequest;
import org.elasticsearch.action.termvectors.TermVectorsRequest;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesInterceptor;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigModel;
import com.amazon.opendistroforelasticsearch.security.user.User;

public class PrivilegesInterceptorImpl extends PrivilegesInterceptor {

    private static final String USER_TENANT = "__user__";
    private static final String EMPTY_STRING = "";

    protected final Logger log = LogManager.getLogger(this.getClass());

    public PrivilegesInterceptorImpl(IndexNameExpressionResolver resolver, ClusterService clusterService, Client client, ThreadPool threadPool) {
        super(resolver, clusterService, client, threadPool);
    }

    private boolean isTenantAllowed(final ActionRequest request, final String action, final User user, final Map<String, Boolean> tenants,
                                    final String requestedTenant) {

        if (!tenants.keySet().contains(requestedTenant)) {
            log.warn("Tenant {} is not allowed for user {}", requestedTenant, user.getName());
            return false;
        } else {

            if (log.isDebugEnabled()) {
                log.debug("request " + request.getClass());
            }

            if (tenants.get(requestedTenant) == Boolean.FALSE && action.startsWith("indices:data/write")) {
                log.warn("Tenant {} is not allowed to write (user: {})", requestedTenant, user.getName());
                return false;
            }
        }

        return true;
    }

    /**
     * return Boolean.TRUE to prematurely deny request
     * return Boolean.FALSE to prematurely allow request
     * return null to go through original eval flow
     *
     */
    @Override
    public Boolean replaceKibanaIndex(final ActionRequest request, final String action, final User user, final DynamicConfigModel config,
                                      final Resolved requestedResolved, final Map<String, Boolean> tenants) {

        final boolean enabled = config.isKibanaMultitenancyEnabled();//config.dynamic.kibana.multitenancy_enabled;

        if (!enabled) {
            return null;
        }

        //next two lines needs to be retrieved from configuration
        final String kibanaserverUsername = config.getKibanaServerUsername();//config.dynamic.kibana.server_username;
        final String kibanaIndexName = config.getKibanaIndexname();//config.dynamic.kibana.index;

        String requestedTenant = user.getRequestedTenant();

        if (log.isDebugEnabled()) {
            log.debug("raw requestedTenant: '" + requestedTenant + "'");
        }

        //intercept when requests are not made by the kibana server and if the kibana index/alias (.kibana) is the only index/alias involved
        final boolean kibanaIndexOnly = !user.getName().equals(kibanaserverUsername) && resolveToKibanaIndexOrAlias(requestedResolved, kibanaIndexName);

        if (requestedTenant == null || requestedTenant.length() == 0) {
            if (log.isTraceEnabled()) {
                log.trace("No tenant, will resolve to " + kibanaIndexName);
            }

            if (kibanaIndexOnly && !isTenantAllowed(request, action, user, tenants, "global_tenant")) {
                return Boolean.TRUE;
            }

            return null;
        }

        if (USER_TENANT.equals(requestedTenant)) {
            requestedTenant = user.getName();
        }

        if (log.isDebugEnabled() && !user.getName().equals(kibanaserverUsername)) {
            //log statements only here
            log.debug("requestedResolved: " + requestedResolved);
        }

        //request not made by the kibana server and user index is the only index/alias involved
        if (!user.getName().equals(kibanaserverUsername) && requestedResolved.getAllIndices().size() == 1
                && requestedResolved.getAllIndices().contains(toUserIndexName(kibanaIndexName, requestedTenant))) {

            if (isTenantAllowed(request, action, user, tenants, requestedTenant)) {
                return Boolean.FALSE;
            }

        }

        //intercept when requests are not made by the kibana server and if the kibana index/alias (.kibana) is the only index/alias involved
        if (kibanaIndexOnly) {

            if (log.isDebugEnabled()) {
                log.debug("requestedTenant: " + requestedTenant);
                log.debug("is user tenant: " + requestedTenant.equals(user.getName()));
            }

            if (!isTenantAllowed(request, action, user, tenants, requestedTenant)) {
                return Boolean.TRUE;
            }

            // TODO handle user tenant in that way that this tenant cannot be specified as
            // regular tenant
            // to avoid security issue

            replaceIndex(request, kibanaIndexName, toUserIndexName(kibanaIndexName, requestedTenant), action);
            return Boolean.FALSE;

        } else if (!user.getName().equals(kibanaserverUsername)) {

            if (log.isTraceEnabled()) {
                log.trace("not a request to only the .kibana index");
                log.trace(user.getName() + "/" + kibanaserverUsername);
                log.trace(requestedResolved + " does not contain only " + kibanaIndexName);
            }

        }

        return null;
    }

    private void replaceIndex(final ActionRequest request, final String oldIndexName, final String newIndexName, final String action) {
        boolean kibOk = false;

        if (log.isDebugEnabled()) {
            log.debug("{} index will be replaced with {} in this {} request", oldIndexName, newIndexName, request.getClass().getName());
        }

        if (request instanceof GetFieldMappingsIndexRequest || request instanceof GetFieldMappingsRequest) {
            return;
        }

        //handle msearch and mget
        //in case of GET change the .kibana index to the userskibanaindex
        //in case of Search add the userskibanaindex
        //if (request instanceof CompositeIndicesRequest) {
        String[] newIndexNames = new String[] { newIndexName };

        // CreateIndexRequest
        if (request instanceof CreateIndexRequest) {
            ((CreateIndexRequest) request).index(newIndexName);
            kibOk = true;
        } else if (request instanceof BulkRequest) {

            for (DocWriteRequest<?> ar : ((BulkRequest) request).requests()) {

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

            kibOk = true;

        } else if (request instanceof MultiGetRequest) {

            for (Item item : ((MultiGetRequest) request).getItems()) {
                item.index(newIndexName);
            }

            kibOk = true;

        } else if (request instanceof MultiSearchRequest) {

            for (SearchRequest ar : ((MultiSearchRequest) request).requests()) {
                ar.indices(newIndexNames);
            }

            kibOk = true;

        } else if (request instanceof MultiTermVectorsRequest) {

            for (TermVectorsRequest ar : (Iterable<TermVectorsRequest>) () -> ((MultiTermVectorsRequest) request).iterator()) {
                ar.index(newIndexName);
            }

            kibOk = true;
        } else if (request instanceof UpdateRequest) {
            ((UpdateRequest) request).index(newIndexName);
            kibOk = true;
        } else if (request instanceof IndexRequest) {
            ((IndexRequest) request).index(newIndexName);
            kibOk = true;
        } else if (request instanceof DeleteRequest) {
            ((DeleteRequest) request).index(newIndexName);
            kibOk = true;
        } else if (request instanceof SingleShardRequest) {
            ((SingleShardRequest<?>) request).index(newIndexName);
            kibOk = true;
        } else if (request instanceof RefreshRequest) {
            ((RefreshRequest) request).indices(newIndexNames); //???
            kibOk = true;
        } else if (request instanceof ReplicationRequest) {
            ((ReplicationRequest<?>) request).index(newIndexName);
            kibOk = true;
        } else if (request instanceof Replaceable) {
            Replaceable replaceableRequest = (Replaceable) request;
            replaceableRequest.indices(newIndexNames);
            kibOk = true;
        } else {
            log.warn("Dont know what to do (1) with {}", request.getClass());
        }

        if (!kibOk) {
            log.warn("Dont know what to do (2) with {}", request.getClass());
        }
    }

    private String toUserIndexName(final String originalKibanaIndex, final String tenant) {

        if (tenant == null) {
            throw new ElasticsearchException("tenant must not be null here");
        }

        return originalKibanaIndex + "_" + tenant.hashCode() + "_" + tenant.toLowerCase().replaceAll("[^a-z0-9]+", EMPTY_STRING);
    }

    private boolean resolveToKibanaIndexOrAlias(final Resolved requestedResolved, final String kibanaIndexName) {
        return (requestedResolved.getAllIndices().size() == 1 && requestedResolved.getAllIndices().contains(kibanaIndexName))
                || (requestedResolved.getAliases().size() == 1 && requestedResolved.getAliases().contains(kibanaIndexName));
    }
}