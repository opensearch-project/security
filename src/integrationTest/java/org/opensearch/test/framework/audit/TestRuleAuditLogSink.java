/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.audit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.sink.AuditLogSink;

public class TestRuleAuditLogSink extends AuditLogSink {
    private static final Logger log = LogManager.getLogger(TestRuleAuditLogSink.class);

    private static volatile AuditLogsRule listener;

    public TestRuleAuditLogSink(String name, Settings settings, String settingsPrefix, AuditLogSink fallbackSink) {
        super(name, settings, settingsPrefix, fallbackSink);
        log.info("Test rule audit log sink created");
    }

    @Override
    protected boolean doStore(AuditMessage auditMessage) {
        log.debug("New audit message received '{}'.", auditMessage);
        AuditLogsRule currentListener = listener;
        if (currentListener != null) {
            currentListener.onAuditMessage(auditMessage);
        }
        return true;
    }

    public static void registerListener(AuditLogsRule auditLogsRule) {
        listener = auditLogsRule;
    }

    public static void unregisterListener() {
        listener = null;
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }
}
