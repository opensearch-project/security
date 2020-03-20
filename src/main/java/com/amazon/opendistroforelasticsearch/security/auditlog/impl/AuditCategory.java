package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import java.util.Collection;
import java.util.EnumSet;
import java.util.Objects;
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
        if (categories == null)
            return set;

        return categories
                .stream()
                .filter(Objects::nonNull)
                .map(String::toUpperCase)
                .map(AuditCategory::valueOf)
                .collect(Collectors.toCollection(() -> set));
    }
}
