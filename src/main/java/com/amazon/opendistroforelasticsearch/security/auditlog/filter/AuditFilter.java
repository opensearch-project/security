package com.amazon.opendistroforelasticsearch.security.auditlog.filter;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportRequest;

import java.util.EnumSet;
import java.util.List;

public class AuditFilter {

    protected static final Logger log = LogManager.getLogger(AuditFilter.class);

    private static boolean checkIgnoredAuditUser(final List<String> ignoredAuditUsers, final String effectiveUser) {
        if (ignoredAuditUsers.size() > 0 && WildcardMatcher.matchAny(ignoredAuditUsers, effectiveUser)) {
            return false;
        }
        return true;
    }

    private static boolean checkIgnoredAuditRequest(final List<String> ignoredAuditRequests, final RestRequest request) {
        if (request != null && ignoredAuditRequests.size() > 0
                && (WildcardMatcher.matchAny(ignoredAuditRequests, request.path()))) {
            return false;
        }
        return true;
    }

    private static boolean checkIgnoredAuditRequest(final List<String> ignoredAuditRequests, final TransportRequest request) {
        if (request != null && ignoredAuditRequests.size() > 0
                && (WildcardMatcher.matchAny(ignoredAuditRequests, request.getClass().getSimpleName()))) {
            return false;
        }
        return true;
    }

    private static boolean checkDisabledCategories(final EnumSet<AuditCategory> disabledCategories, final AuditCategory category) {
        return !disabledCategories.contains(category);
    }

    private static boolean checkInternal(String action) {
        return action == null ||
                (!action.startsWith("internal:")
                        && !action.startsWith("cluster:monitor")
                        && !action.startsWith("indices:monitor"));
    }

    private static boolean checkComplianceOrigin(final AuditLog.Origin origin, final String effectiveUser, final AuditCategory category) {
        if (origin == AuditLog.Origin.LOCAL && effectiveUser == null && category != AuditCategory.COMPLIANCE_EXTERNAL_CONFIG) {
            return false;
        }
        return true;
    }

    private static boolean checkComplianceUser(final List<String> ignoredComplianceUsers, final String effectiveUser, final EnumSet<AuditCategory> complianceCategories, final AuditCategory category) {
        if (complianceCategories.contains(category)) {
            if (ignoredComplianceUsers.size() > 0 && effectiveUser != null
                    && WildcardMatcher.matchAny(ignoredComplianceUsers, effectiveUser)) {
                return false;
            }
        }
        return true;
    }

    private static boolean checkLayerFilter(final boolean enabled, final AuditCategory category) {
        if (!enabled) {
            // ignore for certain categories
            return category == AuditCategory.FAILED_LOGIN
                    || category == AuditCategory.MISSING_PRIVILEGES
                    || category == AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT;
        }
        return true;
    }

    public static boolean checkRestFilter(final AuditCategory category, final String effectiveUser, final RestRequest request, final AuditConfig auditConfig) {
        if (log.isTraceEnabled()) {
            log.trace("Check for REST category:{}, effectiveUser:{}, request:{}", category, effectiveUser, request == null ? null : request.path());
        }

        return checkLayerFilter(auditConfig.isRestAuditingEnabled(), category)
                && checkIgnoredAuditUser(auditConfig.getIgnoredAuditUsers(), effectiveUser)
                && checkIgnoredAuditRequest(auditConfig.getIgnoreAuditRequests(), request)
                && checkDisabledCategories(auditConfig.getDisabledRestCategories(), category);
    }

    public static boolean checkTransportFilter(final AuditCategory category, final String action, final String effectiveUser, final TransportRequest request, final AuditConfig auditConfig) {
        if (log.isTraceEnabled()) {
            log.trace("Check category:{}, action:{}, effectiveUser:{}, request:{}", category, action, effectiveUser, request == null ? null : request.getClass().getSimpleName());
        }

        return checkLayerFilter(auditConfig.isTransportAuditingEnabled(), category)
                && checkInternal(action)
                && checkIgnoredAuditUser(auditConfig.getIgnoredAuditUsers(), effectiveUser)
                && checkIgnoredAuditRequest(auditConfig.getIgnoreAuditRequests(), request)
                && checkDisabledCategories(auditConfig.getDisabledTransportCategories(), category);
    }

    public static boolean checkComplianceFilter(final AuditCategory category, final String effectiveUser, final AuditLog.Origin origin, final AuditConfig auditConfig) {
        if (log.isTraceEnabled()) {
            log.trace("Check for COMPLIANCE category:{}, effectiveUser:{}, origin: {}", category, effectiveUser, origin);
        }

        return checkComplianceOrigin(origin, effectiveUser, category)
                && checkComplianceUser(auditConfig.getIgnoredComplianceUsersForRead(), effectiveUser, EnumSet.of(AuditCategory.COMPLIANCE_DOC_READ, AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ), category)
                && checkComplianceUser(auditConfig.getIgnoredComplianceUsersForWrite(), effectiveUser, EnumSet.of(AuditCategory.COMPLIANCE_DOC_WRITE, AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE), category);
    }
}
