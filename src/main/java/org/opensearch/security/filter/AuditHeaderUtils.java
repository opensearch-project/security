/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.support.WildcardMatcher;

/**
 * Shared header-filtering logic for audit event construction.
 * Used by both AuditActionFilter and AuditTransportInterceptor
 * to ensure consistent behavior.
 */
public final class AuditHeaderUtils {

    /**
     * Request headers that can carry credentials or session identifiers. These are removed from
     * audit events when {@code exclude_sensitive_headers} is enabled. Matching is case-insensitive.
     */
    private static final WildcardMatcher SENSITIVE_HEADERS = WildcardMatcher.from(
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "Set-Cookie",
        "X-Auth-Token"
    ).ignoreCase();

    private AuditHeaderUtils() {}

    /**
     * Returns a filtered copy of the given headers map based on the audit filter config.
     * If {@code exclude_sensitive_headers} is enabled, strips headers that may carry credentials
     * or session identifiers (Authorization, Proxy-Authorization, Cookie, Set-Cookie, X-Auth-Token),
     * case-insensitively. Returns an empty map if headers is null or empty.
     */
    public static Map<String, List<String>> filterHeaders(Map<String, List<String>> headers, AuditConfig.Filter filter) {
        if (headers == null || headers.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, List<String>> filtered = new HashMap<>(headers);
        if (filter.shouldExcludeSensitiveHeaders()) {
            filtered.keySet().removeIf(SENSITIVE_HEADERS);
        }
        return filtered;
    }
}
