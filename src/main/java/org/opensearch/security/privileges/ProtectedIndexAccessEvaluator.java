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

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.RealtimeRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.tasks.Task;

public class ProtectedIndexAccessEvaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());

    private final AuditLog auditLog;
    private final WildcardMatcher indexMatcher;
    private final WildcardMatcher allowedRolesMatcher;
    private final Boolean protectedIndexEnabled;
    private final WildcardMatcher deniedActionMatcher;

    public ProtectedIndexAccessEvaluator(final Settings settings, AuditLog auditLog) {
        this.indexMatcher = WildcardMatcher.from(
            settings.getAsList(ConfigConstants.SECURITY_PROTECTED_INDICES_KEY, ConfigConstants.SECURITY_PROTECTED_INDICES_DEFAULT)
        );
        this.allowedRolesMatcher = WildcardMatcher.from(
            settings.getAsList(
                ConfigConstants.SECURITY_PROTECTED_INDICES_ROLES_KEY,
                ConfigConstants.SECURITY_PROTECTED_INDICES_ROLES_DEFAULT
            )
        );
        this.protectedIndexEnabled = settings.getAsBoolean(
            ConfigConstants.SECURITY_PROTECTED_INDICES_ENABLED_KEY,
            ConfigConstants.SECURITY_PROTECTED_INDICES_ENABLED_DEFAULT
        );
        this.auditLog = auditLog;

        final List<String> indexDeniedActionPatterns = new ArrayList<String>();
        indexDeniedActionPatterns.add("indices:data/write*");
        indexDeniedActionPatterns.add("indices:admin/delete*");
        indexDeniedActionPatterns.add("indices:admin/mapping/delete*");
        indexDeniedActionPatterns.add("indices:admin/mapping/put*");
        indexDeniedActionPatterns.add("indices:admin/freeze*");
        indexDeniedActionPatterns.add("indices:admin/settings/update*");
        indexDeniedActionPatterns.add("indices:admin/aliases");
        indexDeniedActionPatterns.add("indices:admin/close*");
        indexDeniedActionPatterns.add("cluster:admin/snapshot/restore*");
        this.deniedActionMatcher = WildcardMatcher.from(indexDeniedActionPatterns);
    }

    public PrivilegesEvaluatorResponse evaluate(
        final ActionRequest request,
        final Task task,
        final String action,
        final IndexResolverReplacer.Resolved requestedResolved,
        final PrivilegesEvaluatorResponse presponse,
        final SecurityRoles securityRoles
    ) {
        if (!protectedIndexEnabled) {
            return presponse;
        }
        if (!requestedResolved.isLocalAll()
            && indexMatcher.matchAny(requestedResolved.getAllIndices())
            && deniedActionMatcher.test(action)
            && !allowedRolesMatcher.matchAny(securityRoles.getRoleNames())) {
            auditLog.logMissingPrivileges(action, request, task);
            log.warn("{} for '{}' index/indices is not allowed for a regular user", action, indexMatcher);
            presponse.allowed = false;
            return presponse.markComplete();
        }

        if (requestedResolved.isLocalAll()
            && deniedActionMatcher.test(action)
            && !allowedRolesMatcher.matchAny(securityRoles.getRoleNames())) {
            auditLog.logMissingPrivileges(action, request, task);
            log.warn("{} for '_all' indices is not allowed for a regular user", action);
            presponse.allowed = false;
            return presponse.markComplete();
        }
        if ((requestedResolved.isLocalAll() || indexMatcher.matchAny(requestedResolved.getAllIndices()))
            && !allowedRolesMatcher.matchAny(securityRoles.getRoleNames())) {

            final boolean isDebugEnabled = log.isDebugEnabled();
            if (request instanceof SearchRequest) {
                ((SearchRequest) request).requestCache(Boolean.FALSE);
                if (isDebugEnabled) {
                    log.debug("Disable search request cache for this request");
                }
            }

            if (request instanceof RealtimeRequest) {
                ((RealtimeRequest) request).realtime(Boolean.FALSE);
                if (isDebugEnabled) {
                    log.debug("Disable realtime for this request");
                }
            }
        }
        return presponse;
    }
}
