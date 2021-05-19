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

package org.opensearch.security.action.whoami;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.user.User;

public class TransportWhoAmIAction
extends
HandledTransportAction<WhoAmIRequest, WhoAmIResponse> {

    private final AdminDNs adminDNs;
    private final ThreadPool threadPool;

    @Inject
    public TransportWhoAmIAction(final Settings settings,
            final ThreadPool threadPool, final ClusterService clusterService, final TransportService transportService,
            final AdminDNs adminDNs, final ActionFilters actionFilters) {

        super(WhoAmIAction.NAME, transportService, actionFilters, WhoAmIRequest::new);

        this.adminDNs = adminDNs;
        this.threadPool = threadPool;
    }


    @Override
    protected void doExecute(Task task, WhoAmIRequest request, ActionListener<WhoAmIResponse> listener) {
        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final String dn = user==null?threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL):user.getName();
        final boolean isAdmin = adminDNs.isAdminDN(dn);
        final boolean isAuthenticated = isAdmin?true: user != null;
        final boolean isNodeCertificateRequest = HeaderHelper.isInterClusterRequest(threadPool.getThreadContext()) || 
                HeaderHelper.isTrustedClusterRequest(threadPool.getThreadContext());
        
        listener.onResponse(new WhoAmIResponse(dn, isAdmin, isAuthenticated, isNodeCertificateRequest));
        
    }
}
