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
        loggerName = settings.get( settingsPrefix + ".log4j.logger_name","sgaudit");
        auditLogger = LogManager.getLogger(loggerName);
        logLevel = Level.toLevel(settings.get(settingsPrefix + ".log4j.level","INFO").toUpperCase());
        enabled = isLogLevelEnabled(auditLogger, logLevel);
    }

    public boolean isHandlingBackpressure() {
        return !enabled; //no submit to thread pool if not enabled
    }


    public boolean doStore(final AuditMessage msg) {
        if(enabled) {
            logAtLevel(auditLogger, logLevel, msg.toJson());
        }
        return true;
    }

    private boolean isLogLevelEnabled(Logger logger, Level level) {
        boolean isEnabled = false;
        switch(level.toString()) {
            case "TRACE": isEnabled = logger.isTraceEnabled();
            case "DEBUG": isEnabled = logger.isDebugEnabled();
            case "INFO": isEnabled = logger.isInfoEnabled();
            case "WARN": isEnabled = logger.isWarnEnabled();
            case "ERROR": isEnabled = logger.isErrorEnabled();
        }
        return isEnabled;
    }

    private void logAtLevel(Logger logger, Level level, String msg) {
        switch(level.toString()) {
            case "TRACE": logger.trace(msg);
            case "DEBUG": logger.debug(msg);
            case "INFO": logger.info(msg);
            case "WARN": logger.warn(msg);
            case "ERROR": logger.error(msg);
        }
    }
}
