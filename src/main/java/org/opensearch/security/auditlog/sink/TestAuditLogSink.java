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

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;

import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

public class TestAuditLogSink extends AuditLogSink {

    public TestAuditLogSink(String name, Settings settings, String settingsPrefix, AuditLogSink fallbackSink) {
        super(name, settings, settingsPrefix, fallbackSink);
    }

    @Override
    protected boolean doStore(AuditMessage msg) {
        return true;
    }

    public String expandedIndexName(String pattern, String index) {
        DateTimeFormatter formatter = pattern != null ? DateTimeFormat.forPattern(pattern) : null;
        return getExpandedIndexName(formatter, index);
    }
}
