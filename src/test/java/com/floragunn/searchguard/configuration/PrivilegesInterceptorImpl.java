/*
 * Copyright 2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.configuration;

import java.util.Map;
import java.util.Set;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.configuration.PrivilegesEvaluator.IndexType;
import com.floragunn.searchguard.user.User;

public class PrivilegesInterceptorImpl extends PrivilegesInterceptor {

    public static int count = 0;
    
    @Inject
    public PrivilegesInterceptorImpl(IndexNameExpressionResolver resolver, ClusterService clusterService, Client client) {
        super(resolver, clusterService, client);
    }

    @Override
    public boolean replaceKibanaIndex(ActionRequest request, String action, User user, Settings config,
            Set<String> requestedResolvedIndices, Map<String, Boolean> tenants) {
        count++;
        return false;
    }

    @Override
    public boolean replaceAllowedIndices(ActionRequest request, String action, User user, Settings config, Set<IndexType> leftOvers) {
        count++;
        return false;
    }

    
}
