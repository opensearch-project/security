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

package org.opensearch.security.auditlog.sink;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;

public final class Log4JSink extends AuditLogSink {

    final Logger auditLogger;
    final String loggerName;
    final Level logLevel;
    final boolean enabled;

    public Log4JSink(final String name, final Settings settings, final String settingsPrefix, AuditLogSink fallbackSink) {
        super(name, settings, settingsPrefix, fallbackSink);
        loggerName = settings.get(settingsPrefix + ".log4j.logger_name", "audit");
        auditLogger = LogManager.getLogger(loggerName);
        logLevel = Level.toLevel(settings.get(settingsPrefix + ".log4j.level", "INFO").toUpperCase());
        enabled = auditLogger.isEnabled(logLevel);
    }

    public boolean isHandlingBackpressure() {
        return !enabled; // no submit to thread pool if not enabled
    }

    public boolean doStore(final AuditMessage msg) {
        if (enabled) {
            auditLogger.log(logLevel, msg.toJson());
        }
        return true;
    }
}
