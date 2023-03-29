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

package org.opensearch.security.privileges;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.greenrobot.eventbus.Subscribe;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import java.util.Set;

public class RestLayerPrivilegesEvaluator {
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final ClusterService clusterService;

    private final AuditLog auditLog;
    private ThreadContext threadContext;

    private final ClusterInfoHolder clusterInfoHolder;
    private ConfigModel configModel;
    private DynamicConfigModel dcm;
    private final NamedXContentRegistry namedXContentRegistry;

    public RestLayerPrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool,
                               final ConfigurationRepository configurationRepository,
                               AuditLog auditLog, final Settings settings, final ClusterInfoHolder clusterInfoHolder,
                               NamedXContentRegistry namedXContentRegistry) {

        super();
        this.clusterService = clusterService;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();

        this.clusterInfoHolder = clusterInfoHolder;
        this.namedXContentRegistry = namedXContentRegistry;
    }

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;
    }

    private SecurityRoles getSecurityRoles(Set<String> roles) {
        return configModel.getSecurityRoles().filter(roles);
    }

    public boolean isInitialized() {
        return configModel !=null && configModel.getSecurityRoles() != null && dcm != null;
    }

    public PrivilegesEvaluatorResponse evaluate(final User user, String action0) {

        if (!isInitialized()) {
            throw new OpenSearchSecurityException("OpenSearch Security is not initialized.");
        }

        final PrivilegesEvaluatorResponse presponse = new PrivilegesEvaluatorResponse();

        final TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);

        Set<String> mappedRoles = mapRoles(user, caller);

        presponse.resolvedSecurityRoles.addAll(mappedRoles);
        final SecurityRoles securityRoles = getSecurityRoles(mappedRoles);

        final boolean isDebugEnabled = log.isDebugEnabled();
        if (isDebugEnabled) {
            log.debug("Evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("Action: {}", action0);
            log.debug("Mapped roles: {}", mappedRoles.toString());
        }
        if(!securityRoles.impliesExtensionPermissionPermission(action0)) {
            presponse.missingPrivileges.add(action0);
            presponse.allowed = false;
            log.info("No extension-level perm match for {} [Action [{}]] [RolesChecked {}]. No permissions for {}",  user, action0,
                    securityRoles.getRoleNames(), presponse.missingPrivileges);
            return presponse;
        } else {
            if (isDebugEnabled) {
                log.debug("Allowed because we have extension permissions for {}", action0);
            }
            presponse.allowed = true;
            return presponse;
        }
    }

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }
}
