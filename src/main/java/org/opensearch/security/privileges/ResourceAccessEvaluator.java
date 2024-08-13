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
import org.opensearch.action.ActionRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.user.User;

import java.util.List;
import java.util.Set;

public class ResourceAccessEvaluator {
    protected final Logger log = LogManager.getLogger(this.getClass());
    private ConfigModel configModel;

    public ResourceAccessEvaluator() {}

    @Subscribe
    public void onConfigModelChanged(final ConfigModel configModel) {
        this.configModel = configModel;
    }

    boolean isInitialized() {
        return configModel != null && configModel.getSecurityRoles() != null;
    }

    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request,
                                                final String action,
                                                final SecurityRoles securityRoles,
                                                final User user,
                                                final ClusterService clusterService) {
        if (!isInitialized()) {
            throw new OpenSearchSecurityException("OpenSearch Security is not initialized.");
        }

        final PrivilegesEvaluatorResponse presponse = new PrivilegesEvaluatorResponse();

        final boolean isDebugEnabled = log.isDebugEnabled();
        if (isDebugEnabled) {
            log.debug("Evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("Action: {}", action);
            log.debug("Resource: {}", request.getRequestedResources());
            log.debug("Security roles: {}", securityRoles.toString());
        }

        List<String> resourcesRequested = request.getRequestedResources();
        if (resourcesRequested == null || resourcesRequested.isEmpty()) {
            presponse.allowed = true;
            return presponse;
        }
        presponse.allowed = true;
        for (String resource : resourcesRequested) {
            if (!securityRoles.impliesResourcePermission(resource)) {
                presponse.missingPrivileges.add(action);
                presponse.allowed = false;
                log.info(
                        "No permission match for {} [Action [{}]] [RolesChecked {}]. No permissions for {}",
                        user,
                        action,
                        securityRoles.getRoleNames(),
                        presponse.missingPrivileges
                );
            }
        }
        return presponse;
    }

    Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }
}
