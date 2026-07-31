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

import java.util.regex.Pattern;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;

public final class Log4JSink extends AuditLogSink {

    // MDC key constants — single source of truth for put/remove consistency
    static final String MDC_CATEGORY = "audit_category";
    static final String MDC_ACTION = "audit_action";
    static final String MDC_USER = "audit_user";
    static final String MDC_REQUEST_TYPE = "audit_request_type";

    /** Characters unsafe for filenames + control chars — pre-compiled for performance. */
    private static final Pattern UNSAFE_MDC_CHARS = Pattern.compile("[:/\\\\*?\"<>|\\[\\]\\p{Cntrl}]");

    final Logger auditLogger;
    final String loggerName;
    final Level logLevel;
    final boolean enabled;
    final boolean mdcRoutingEnabled;
    final Integer maximumIndexCharactersPerMessage;

    public Log4JSink(final String name, final Settings settings, final String settingsPrefix, AuditLogSink fallbackSink) {
        super(name, settings, settingsPrefix, fallbackSink);
        loggerName = settings.get(settingsPrefix + ".log4j.logger_name", "audit");
        auditLogger = LogManager.getLogger(loggerName);
        logLevel = Level.toLevel(settings.get(settingsPrefix + ".log4j.level", "INFO").toUpperCase());
        maximumIndexCharactersPerMessage = settings.getAsInt(
            settingsPrefix + ".log4j.maximum_index_characters_per_message",
            Integer.MAX_VALUE
        );
        enabled = auditLogger.isEnabled(logLevel);
        mdcRoutingEnabled = settings.getAsBoolean(settingsPrefix + ".log4j.enable_mdc_routing", false);
    }

    public boolean isHandlingBackpressure() {
        return !enabled; // no submit to thread pool if not enabled
    }

    public boolean doStore(final AuditMessage msg) {
        if (enabled) {
            if (mdcRoutingEnabled) {
                try {
                    // Push audit attributes into Log4j MDC so operators can use
                    // RoutingAppender with $${ctx:audit_category} etc. to split logs.
                    // WARNING: Do not use audit_user as a RoutingAppender routing key for file paths —
                    // it is unbounded/attacker-influenceable and could cause inode/disk exhaustion.
                    // Prefer audit_category (bounded enum) for file-based routing.
                    ThreadContext.put(MDC_CATEGORY, sanitizeForMdc(msg.getCategory() != null ? msg.getCategory().name() : null));
                    ThreadContext.put(MDC_ACTION, sanitizeForMdc(msg.getPrivilege()));
                    ThreadContext.put(MDC_USER, sanitizeForMdc(msg.getEffectiveUser()));
                    ThreadContext.put(MDC_REQUEST_TYPE, sanitizeForMdc(msg.getRequestType()));

                    msg.toJsonSplitIndices(maximumIndexCharactersPerMessage).forEach(message -> auditLogger.log(logLevel, message));
                } finally {
                    ThreadContext.remove(MDC_CATEGORY);
                    ThreadContext.remove(MDC_ACTION);
                    ThreadContext.remove(MDC_USER);
                    ThreadContext.remove(MDC_REQUEST_TYPE);
                }
            } else {
                msg.toJsonSplitIndices(maximumIndexCharactersPerMessage).forEach(message -> auditLogger.log(logLevel, message));
            }
        }
        return true;
    }

    /**
     * Sanitizes a value for safe use in Log4j MDC, particularly when operators
     * use MDC values in RoutingAppender file paths. Replaces characters that are
     * problematic in filenames (e.g., colons in action names like "indices:data/write/index")
     * and control characters that could enable log-forging attacks.
     * These MDC keys are owned by the audit sink — no other code should set them.
     */
    static String sanitizeForMdc(String value) {
        if (value == null || value.isEmpty()) {
            return "unknown";
        }
        return UNSAFE_MDC_CHARS.matcher(value).replaceAll("_");
    }
}
