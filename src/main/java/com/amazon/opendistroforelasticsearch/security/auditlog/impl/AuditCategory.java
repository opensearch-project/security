package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;

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

    private static Logger log = LogManager.getLogger(AuditCategory.class);

    public static EnumSet<AuditCategory> parse(final List<String> categories) {
        EnumSet<AuditCategory> set = EnumSet.noneOf(AuditCategory.class);
        if (categories == null)
            return set;

        categories
                .stream()
                .filter(Objects::nonNull)
                .map(category -> category.toUpperCase())
                .forEach(category -> {
                    try {
                        set.add(AuditCategory.valueOf(category));
                    } catch (IllegalArgumentException ex) {
                        log.error("Invalid category type: {} Exception: {}", category, ex.getMessage());
                    }
                });
        return set;
    }
}
