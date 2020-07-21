package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

import com.google.common.collect.ImmutableSet;
import org.elasticsearch.common.settings.Settings;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

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

    public static Set<AuditCategory> parse(final Collection<String> categories) {
        if (categories.isEmpty())
            return Collections.emptySet();

        return categories
                .stream()
                .map(String::toUpperCase)
                .map(AuditCategory::valueOf)
                .collect(ImmutableSet.toImmutableSet());
    }

    public static Set<AuditCategory> from(final Settings settings, final String key) {
        return parse(ConfigConstants.getSettingAsSet(settings, key, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT, true));
    }
}
