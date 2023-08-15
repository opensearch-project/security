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

import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.greenrobot.eventbus.Subscribe;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

public class RestLayerPrivilegesEvaluator {
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final ClusterService clusterService;
    private final AuditLog auditLog;
    private ThreadContext threadContext;
    private final ClusterInfoHolder clusterInfoHolder;
    private ConfigModel configModel;
    private DynamicConfigModel dcm;
    private final AtomicReference<NamedXContentRegistry> namedXContentRegistry;

    public RestLayerPrivilegesEvaluator(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        AuditLog auditLog,
        final ClusterInfoHolder clusterInfoHolder,
        AtomicReference<NamedXContentRegistry> namedXContentRegistry
    ) {
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
        return configModel != null && configModel.getSecurityRoles() != null && dcm != null;
    }

    public PrivilegesEvaluatorResponse evaluate(final User user, Set<String> actions) {

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
            log.debug("Action: {}", actions);
            log.debug("Mapped roles: {}", mappedRoles.toString());
        }

        for (String action : actions) {
            if (!securityRoles.impliesClusterPermissionPermission(action)) {
                presponse.missingPrivileges.add(action);
                presponse.allowed = false;
                log.info(
                    "No permission match for {} [Action [{}]] [RolesChecked {}]. No permissions for {}",
                    user,
                    action,
                    securityRoles.getRoleNames(),
                    presponse.missingPrivileges
                );
            } else {
                if (isDebugEnabled) {
                    log.debug("Allowed because we have permissions for {}", actions);
                }
                presponse.allowed = true;

                // break the loop as we found the matching permission
                break;
            }
        }

        return presponse;
    }

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }

}
