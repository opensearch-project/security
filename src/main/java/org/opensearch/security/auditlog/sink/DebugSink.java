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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;

public final class DebugSink extends AuditLogSink {

    final Logger log = LogManager.getLogger(DebugSink.class);

    public DebugSink(String name, Settings settings, AuditLogSink fallbackSink) {
        super(name, settings, null, fallbackSink);
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }

    @Override
    public boolean doStore(final AuditMessage msg) {
        log.info("AUDIT_LOG: " + msg.toPrettyString());
        return true;
    }

}
