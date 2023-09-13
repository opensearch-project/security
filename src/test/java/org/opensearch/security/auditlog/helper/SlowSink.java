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

package org.opensearch.security.auditlog.helper;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.sink.AuditLogSink;

public class SlowSink extends AuditLogSink {

    public SlowSink(String name, Settings settings, Settings sinkSetting, AuditLogSink fallbackSink) {
        super(name, settings, null, fallbackSink);
    }

    public boolean doStore(AuditMessage msg) {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException ignored) {}

        return true;
    }
}
