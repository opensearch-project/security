package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

import org.elasticsearch.common.settings.Settings;

import java.util.Collection;
import java.util.EnumSet;
import java.util.stream.Collectors;

public enum AuditCategory {
    BAD_HEADERS,
    FAILED_LOGIN,
    MISSING_PRIVILEGES,
    GRANTED_PRIVILEGES,
    OPENDISTRO_SECURITY_INDEX_ATTEMPT,
    SSL_EXCEPTION,
    AUTHENTICATED,
    COMPLIANCE_DOC_READ,
    COMPLIANCE_DOC_WRITE,
    COMPLIANCE_EXTERNAL_CONFIG,
    COMPLIANCE_INTERNAL_CONFIG_READ,
    COMPLIANCE_INTERNAL_CONFIG_WRITE;

    public static EnumSet<AuditCategory> parse(final Collection<String> categories) {
        EnumSet<AuditCategory> set = EnumSet.noneOf(AuditCategory.class);
        if (categories.isEmpty())
            return set;

        return categories
                .stream()
                .map(String::toUpperCase)
                .map(AuditCategory::valueOf)
                .collect(Collectors.toCollection(() -> set));
    }

    public static EnumSet<AuditCategory> from(final Settings settings, final String key) {
        return parse(ConfigConstants.getSettingAsSet(settings, key, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT, true));
    }
}
