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
import java.util.function.Predicate;
import java.util.regex.Pattern;

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


public class RestLayerPrivilegesEvaluator {
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final ClusterService clusterService;
    private final AuditLog auditLog;
    private ThreadContext threadContext;
    private final ClusterInfoHolder clusterInfoHolder;
    private ConfigModel configModel;
    private DynamicConfigModel dcm;
    private final AtomicReference<NamedXContentRegistry> namedXContentRegistry;

    public RestLayerPrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool,
                                        final ConfigurationRepository configurationRepository,
                                        AuditLog auditLog, final Settings settings, final ClusterInfoHolder clusterInfoHolder,
                                        AtomicReference<NamedXContentRegistry> namedXContentRegistry) {

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

        if (!securityRoles.impliesClusterPermissionPermission(action0) && !impliesLegacyPermission(action0, securityRoles)) {
            presponse.missingPrivileges.add(action0);
            presponse.allowed = false;
            log.info("No permission match for {} [Action [{}]] [RolesChecked {}]. No permissions for {}",  user, action0,
                    securityRoles.getRoleNames(), presponse.missingPrivileges);
        } else {
            if (isDebugEnabled) {
                log.debug("Allowed because we have extension permissions for {}", action0);
            }
            presponse.allowed = true;
        }
        return presponse;
    }

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }

    /**
     * Checks if the route is accessible via legacy naming convention.
     * We check against cluster permissions because the legacy convention for cluster permissions map 1-1 with a transport
     * action call initiated via REST API handler. Hence we use the same to allow/block request forwarding to extensions.
     * This ensures backwards-compatibility
     *
     *
     * NOTE: THIS CHECK WILL BE REMOVED ONCE ALL ACTIONS HAVE BEEN MIGRATED TO THE NEW CONVENTION
     *
     * E.g For extension `hw`, following are two possible ways actions an be defined in roles:
     *
     * extension_hw_full:
     *   reserved: true
     *   cluster_permissions:
     *     - 'extension:hw/greet'
     *
     * legacy_hw_full:
     *   reserved: true
     *   cluster_permissions:
     *     - 'cluster:admin/opensearch/hw/greet'
     *
     *
     * @param action - The action to be checked against its legacy version
     * @return true, if a legacy version was found and validated, false otherwise
     */
    private boolean impliesLegacyPermission(String action, SecurityRoles roles) {
        boolean isAlreadyLegacy = action.startsWith("cluster:admin/open");
        if (isAlreadyLegacy) {
            return false; // this check was already made, so return false
        }

        log.info("Checking legacy permissions for {}", action);

        action = action.split(":")[1]; // e.g. `hw:greet` would check for action `greet` for extension `hw`

        /* Regex: `/(?:cluster:admin\/\b(open(distro|search))\b\/[a-zA-Z]+\/|\*)action\/?(?:\*|[\/a-zA-Z0-9]*)/gm`
         *  matches:
         *  *action*
         *  cluster:admin/opensearch/abcd/action
         *  cluster:admin/opensearch/abcd/action*
         *  cluster:admin/opensearch/abcd/action/*
         *  cluster:admin/opensearch/abcd/action/a/*
         *  cluster:admin/opensearch/abcd/action/a/b/c
         *  *action*
         *  *action/abc
         *
         *  doesn't match:
         *  action
         *  action*
         *  action/
         *  indices:admin/action/
         *
         *  For more details on regex, please visit regex101.com and paste the regex
         */
        String legacyActionMatchRegex = "(?:cluster:admin/\\\\b(open(distro|search))\\\\b/[a-zA-Z]+/|\\\\*)greet/?(?:\\\\*|[/a-zA-Z0-9]*)";

        String regex = String.format(legacyActionMatchRegex, action);
        Predicate<String> pattern = Pattern.compile(regex).asPredicate();

        return roles.impliesLegacyPermissions(pattern);
    }
}
