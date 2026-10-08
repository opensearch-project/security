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

import org.opensearch.security.auditlog.AuditLog.Origin;

import static org.opensearch.security.auditlog.AuditLog.Origin.REST;
import static org.opensearch.security.auditlog.AuditLog.Origin.TRANSPORT;

public enum AuditCategory {
    BAD_HEADERS(REST, TRANSPORT),
    FAILED_LOGIN(REST, TRANSPORT),
    MISSING_PRIVILEGES(REST, TRANSPORT),
    GRANTED_PRIVILEGES(REST, TRANSPORT),
    OPENDISTRO_SECURITY_INDEX_ATTEMPT(TRANSPORT),
    SSL_EXCEPTION(REST, TRANSPORT),
    AUTHENTICATED(REST, TRANSPORT),
    INDEX_EVENT(TRANSPORT),
    COMPLIANCE_DOC_READ(),
    COMPLIANCE_DOC_WRITE(),
    COMPLIANCE_EXTERNAL_CONFIG(),
    COMPLIANCE_INTERNAL_CONFIG_READ(),
    COMPLIANCE_INTERNAL_CONFIG_WRITE(),
    CLUSTER_SETTINGS_CHANGED(TRANSPORT),
    INDEX_SETTINGS_CHANGED(TRANSPORT),
    API_TOKEN_WRITE(),
    // REST-origin requests audited on the transport layer support either legacy filter.
    REQUEST_AUDIT(REST, TRANSPORT),
    TRANSPORT_AUDIT(TRANSPORT),
    RESOURCE_ACCESS_GRANTED(REST, TRANSPORT),
    RESOURCE_ACCESS_DENIED(REST, TRANSPORT),
    RESOURCE_SHARING_CHANGED(REST, TRANSPORT);

    private final Set<Origin> filterLayers;

    AuditCategory(Origin... filterLayers) {
        this.filterLayers = Set.of(filterLayers);
    }

    /**
     * Whether a legacy layer-specific exclusion setting accepts this category.
     * Every category supports unified disabled_categories, including categories without a REST/transport layer.
     */
    public boolean supportsLayerFilter(Origin layer) {
        return filterLayers.contains(layer);
    }

    /**
     * Categories that require an authentication/authorization layer to produce events.
     * These will never fire in SSL-only or disabled modes.
     */
    public static final Set<AuditCategory> AUTH_ONLY_CATEGORIES = ImmutableSet.of(
        AUTHENTICATED,
        FAILED_LOGIN,
        GRANTED_PRIVILEGES,
        MISSING_PRIVILEGES,
        OPENDISTRO_SECURITY_INDEX_ATTEMPT,
        API_TOKEN_WRITE,
        RESOURCE_ACCESS_GRANTED,
        RESOURCE_ACCESS_DENIED,
        RESOURCE_SHARING_CHANGED
    );

    public static Set<AuditCategory> parse(final Collection<String> categories) {
        if (categories.isEmpty()) return Collections.emptySet();
        if (categories.size() == 1 && "NONE".equalsIgnoreCase(categories.iterator().next())) {
            return Collections.emptySet();
        }

        return categories.stream().map(String::toUpperCase).map(AuditCategory::valueOf).collect(ImmutableSet.toImmutableSet());
    }
}
