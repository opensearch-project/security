package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.ArrayList;
import java.util.List;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.securityconf.SecurityRoles;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;

public class OpenDistroProtectedIndexAccessEvaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());

    private final AuditLog auditLog;
    private final WildcardMatcher indexMatcher;
    private final WildcardMatcher allowedRolesMatcher;
    private final Boolean protectedIndexEnabled;
    private final WildcardMatcher deniedActionMatcher;


    public OpenDistroProtectedIndexAccessEvaluator(final Settings settings, AuditLog auditLog) {
        this.indexMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_DEFAULT));
        this.allowedRolesMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_DEFAULT));
        this.protectedIndexEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_DEFAULT);
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

    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final Task task, final String action, final IndexResolverReplacer.Resolved requestedResolved,
                                                final PrivilegesEvaluatorResponse presponse, final SecurityRoles securityRoles) {
        if (!protectedIndexEnabled) {
            return presponse;
        }
        if (indexMatcher.matchAny(requestedResolved.getAllIndices())
                && deniedActionMatcher.test(action)
                && !allowedRolesMatcher.matchAny(securityRoles.getRoleNames())) {
            auditLog.logMissingPrivileges(action, request, task);
            log.warn(action + " for '{}' index/indices is not allowed for a regular user", indexMatcher);
            presponse.allowed = false;
            return presponse.markComplete();
        }

        if (requestedResolved.isLocalAll()
                && deniedActionMatcher.test(action)
                && !allowedRolesMatcher.matchAny(securityRoles.getRoleNames())) {
            auditLog.logMissingPrivileges(action, request, task);
            log.warn(action + " for '_all' indices is not allowed for a regular user");
            presponse.allowed = false;
            return presponse.markComplete();
        }
        if((indexMatcher.matchAny(requestedResolved.getAllIndices())
                || requestedResolved.isLocalAll())
                && !allowedRolesMatcher.matchAny(securityRoles.getRoleNames())) {

            if(request instanceof SearchRequest) {
                ((SearchRequest)request).requestCache(Boolean.FALSE);
                if(log.isDebugEnabled()) {
                    log.debug("Disable search request cache for this request");
                }
            }

            if(request instanceof RealtimeRequest) {
                ((RealtimeRequest) request).realtime(Boolean.FALSE);
                if(log.isDebugEnabled()) {
                    log.debug("Disable realtime for this request");
                }
            }
        }
        return presponse;
    }
}
