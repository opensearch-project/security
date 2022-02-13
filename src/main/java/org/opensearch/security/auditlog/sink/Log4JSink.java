/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.auditlog.sink;

import org.apache.logging.log4j.Level;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
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
        auditLogger = LoggerFactory.getLogger(loggerName);
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
