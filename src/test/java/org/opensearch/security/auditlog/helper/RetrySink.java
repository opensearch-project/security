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

public class RetrySink extends AuditLogSink {

    private static int failCount = 0;
    private static AuditMessage msg = null;

    public RetrySink(String name, Settings settings, String sinkPrefix, AuditLogSink fallbackSink) {
        super(name, settings, null, new FailingSink("", settings, "", null));
        failCount = 0;
        log.debug("init");
    }

    @Override
    protected synchronized boolean doStore(AuditMessage msg) {
        if (failCount++ < 5) {
            log.debug("Fail " + failCount);
            return false;
        }
        log.debug("doStore ok");
        RetrySink.msg = msg;
        return true;
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }

    public static void init() {
        RetrySink.failCount = 0;
        msg = null;
    }

    public static AuditMessage getMsg() {
        return msg;
    }

}
