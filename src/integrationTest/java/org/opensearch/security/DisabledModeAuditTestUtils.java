/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security;

import java.util.Map;

import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.audit.TestRuleAuditLogSink;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

/**
 * Shared test utilities for disabled-mode audit integration tests.
 * Reduces duplication between StandaloneAuditDisabledModeTest and
 * StandaloneAuditDisabledModeToggleTest.
 */
public final class DisabledModeAuditTestUtils {

    private DisabledModeAuditTestUtils() {
        // utility class
    }

    /**
     * Creates a standard LocalCluster configured for disabled security mode with
     * audit logging enabled, including compliance write/read watched settings.
     */
    public static LocalCluster createDisabledModeAuditCluster() {
        return new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .anonymousAuth(false)
            .loadConfigurationIntoIndex(false)
            .nodeSettings(
                Map.of(
                    ConfigConstants.SECURITY_DISABLED,
                    true,
                    ConfigConstants.SECURITY_AUDIT_ENABLE_STANDALONE,
                    true,
                    "plugins.security.audit.type",
                    TestRuleAuditLogSink.class.getName(),
                    "plugins.security.audit.config.log_request_body",
                    true,
                    "plugins.security.audit.config.resolve_indices",
                    true,
                    "plugins.security.audit.config.resolve_bulk_requests",
                    true,
                    ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES,
                    "watched-*",
                    ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                    "read-watched"
                )
            )
            .sslOnly(true)
            .build();
    }

    /**
     * Checks whether an audit message belongs to the given category and contains
     * the specified index name in its {@link AuditMessage#INDICES} field.
     */
    public static boolean messageMatchesIndex(AuditMessage msg, AuditCategory category, String indexName) {
        if (msg.getCategory() != category) return false;
        Map<String, Object> fields = msg.getAsMap();
        Object indices = fields.get(AuditMessage.INDICES);
        if (indices == null) return false;
        String[] indexArr = (String[]) indices;
        for (String idx : indexArr) {
            if (indexName.equals(idx)) return true;
        }
        return false;
    }

    /**
     * Checks whether an audit message contains the specified index name in its
     * {@link AuditMessage#INDICES} field, regardless of category.
     */
    public static boolean messageHasIndex(AuditMessage msg, String indexName) {
        Map<String, Object> fields = msg.getAsMap();
        Object indices = fields.get(AuditMessage.INDICES);
        if (indices == null) return false;
        String[] indexArr = (String[]) indices;
        for (String idx : indexArr) {
            if (indexName.equals(idx)) return true;
        }
        return false;
    }
}
