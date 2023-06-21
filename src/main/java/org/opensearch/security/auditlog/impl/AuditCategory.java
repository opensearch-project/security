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

package org.opensearch.security.auditlog.impl;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import com.google.common.collect.ImmutableSet;

public enum AuditCategory {
    BAD_HEADERS,
    FAILED_LOGIN,
    MISSING_PRIVILEGES,
    GRANTED_PRIVILEGES,
    OPENDISTRO_SECURITY_INDEX_ATTEMPT,
    SSL_EXCEPTION,
    AUTHENTICATED,
    INDEX_EVENT,
    COMPLIANCE_DOC_READ,
    COMPLIANCE_DOC_WRITE,
    COMPLIANCE_EXTERNAL_CONFIG,
    COMPLIANCE_INTERNAL_CONFIG_READ,
    COMPLIANCE_INTERNAL_CONFIG_WRITE;

    public static Set<AuditCategory> parse(final Collection<String> categories) {
        if (categories.isEmpty()) return Collections.emptySet();

        return categories.stream().map(String::toUpperCase).map(AuditCategory::valueOf).collect(ImmutableSet.toImmutableSet());
    }
}
