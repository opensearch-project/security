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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.rest;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestRequest.Method.POST;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.SortedMap;
import com.google.common.base.Strings;

import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigFactory;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.RoleMappings;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;

import com.google.common.collect.ImmutableList;

public class TenantInfoAction extends BaseRestHandler {
    private static final List<Route> routes = ImmutableList.of(
            new Route(GET, "/_opendistro/_security/tenantinfo"),
            new Route(POST, "/_opendistro/_security/tenantinfo")
    );

    private final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evaluator;
    private final ThreadContext threadContext;
    private final ClusterService clusterService;
    private final AdminDNs adminDns;
    private final ConfigurationRepository configurationRepository;

    public TenantInfoAction(final Settings settings, final RestController controller, 
    		final PrivilegesEvaluator evaluator, final ThreadPool threadPool, final ClusterService clusterService, final AdminDNs adminDns,
                            final ConfigurationRepository configurationRepository) {
        super();
        this.threadContext = threadPool.getThreadContext();
        this.evaluator = evaluator;
        this.clusterService = clusterService;
        this.adminDns = adminDns;
        this.configurationRepository = configurationRepository;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder(); //NOSONAR
                BytesRestResponse response = null;
                
                try {

                    final User user = (User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    
                    //only allowed for admins or the kibanaserveruser
                    if(!isAuthorized()) {
                        response = new BytesRestResponse(RestStatus.FORBIDDEN,"");
                    } else {

                    	builder.startObject();
	
                    	final SortedMap<String, IndexAbstraction> lookup = clusterService.state().metadata().getIndicesLookup();
                    	for(final String indexOrAlias: lookup.keySet()) {
                    		final String tenant = tenantNameForIndex(indexOrAlias);
                    		if(tenant != null) {
                    			builder.field(indexOrAlias, tenant);
                    		}
                    	}

	                    builder.endObject();
	
	                    response = new BytesRestResponse(RestStatus.OK, builder);
                    }
                } catch (final Exception e1) {
                    log.error(e1);
                    builder = channel.newBuilder(); //NOSONAR
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if(builder != null) {
                        builder.close();
                    }
                }

                channel.sendResponse(response);
            }
        };
    }

    private boolean isAuthorized() {
        final User user = (User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

        if (user == null) {
            return false;
        }

        // check if the user is a kibanauser or super admin
        if (user.getName().equals(evaluator.kibanaServerUsername()) || adminDns.isAdmin(user)) {
            return true;
        }

        // If user check failed by name and admin, check if the users belong to kibana opendistro role
        final SecurityDynamicConfiguration<?> rolesMappingConfiguration = load(CType.ROLESMAPPING, true);

        // check if kibanaOpendistroRole is present in RolesMapping and if yes, check if user is a part of this role
        if (rolesMappingConfiguration != null) {
            String kibanaOpendistroRole = evaluator.kibanaOpendistroRole();
            if (Strings.isNullOrEmpty(kibanaOpendistroRole)) {
                return false;
            }
            RoleMappings roleMapping = (RoleMappings) rolesMappingConfiguration.getCEntries().getOrDefault(kibanaOpendistroRole, null);
            return roleMapping != null && roleMapping.getUsers().contains(user.getName());
        }

        return false;
    }

    private final SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = configurationRepository.getConfigurationsFromIndex(Collections.singleton(config), logComplianceEvent).get(config).deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

    private String tenantNameForIndex(String index) {
    	String[] indexParts;
    	if(index == null 
    			|| (indexParts = index.split("_")).length != 3
    			) {
    		return null;
    	}
    	
    	
    	if(!indexParts[0].equals(evaluator.kibanaIndex())) {
    		return null;
    	}
    	
    	try {
			final int expectedHash = Integer.parseInt(indexParts[1]);
			final String sanitizedName = indexParts[2];
			
			for(String tenant: evaluator.getAllConfiguredTenantNames()) {
				if(tenant.hashCode() == expectedHash && sanitizedName.equals(tenant.toLowerCase().replaceAll("[^a-z0-9]+",""))) {
					return tenant;
				}
			}

			return "__private__";
		} catch (NumberFormatException e) {
			log.warn("Index {} looks like a Security tenant index but we cannot parse the hashcode so we ignore it.", index);
			return null;
		}
    }

    @Override
    public String getName() {
        return "Tenant Info Action";
    }
    
    
}
