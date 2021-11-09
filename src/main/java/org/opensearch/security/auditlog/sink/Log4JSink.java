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
        enabled = auditLogger.isEnabled(logLevel);
    }

    public boolean isHandlingBackpressure() {
        return !enabled; //no submit to thread pool if not enabled
    }


    public boolean doStore(final AuditMessage msg) {
        if(enabled) {
            auditLogger.log(logLevel, msg.toJson());
        }
        return true;
    }

}
