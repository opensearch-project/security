/*
 * Copyright 2015-2017 floragunn GmbH
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

package com.floragunn.searchguard.action.whoami;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;

public class TransportWhoAmIAction
extends
HandledTransportAction<WhoAmIRequest, WhoAmIResponse> {

    private final AdminDNs adminDNs;

    @Inject
    public TransportWhoAmIAction(final Settings settings,
            final ThreadPool threadPool, final ClusterService clusterService, final TransportService transportService,
            final AdminDNs adminDNs, final ActionFilters actionFilters, final IndexNameExpressionResolver indexNameExpressionResolver) {

        super(settings, WhoAmIAction.NAME, threadPool, transportService, actionFilters, indexNameExpressionResolver, WhoAmIRequest::new);

        this.adminDNs = adminDNs;
    }


    @Override
    protected void doExecute(WhoAmIRequest request, ActionListener<WhoAmIResponse> listener) {
        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.SG_USER);
        final String dn = user==null?threadPool.getThreadContext().getTransient(ConfigConstants.SG_SSL_TRANSPORT_PRINCIPAL):user.getName();
        final boolean isAdmin = adminDNs.isAdminDN(dn);
        final boolean isAuthenticated = isAdmin?true: user != null;
        final boolean isNodeCertificateRequest = HeaderHelper.isInterClusterRequest(threadPool.getThreadContext()) || 
                HeaderHelper.isTrustedClusterRequest(threadPool.getThreadContext());
        
        listener.onResponse(new WhoAmIResponse(dn, isAdmin, isAuthenticated, isNodeCertificateRequest));
        
    }
}
