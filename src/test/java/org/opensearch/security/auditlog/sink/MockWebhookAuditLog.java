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

public class MockWebhookAuditLog extends WebhookSink {

    public String payload = null;
    public String url = null;

    public MockWebhookAuditLog(Settings settings, String settingsPrefix, AuditLogSink fallback) throws Exception {
        super("test", settings, settingsPrefix, null, fallback);
    }

    @Override
    protected boolean doPost(String url, String payload) {
        this.payload = payload;
        return true;
    }

    @Override
    protected boolean doGet(String url) {
        this.url = url;
        return true;
    }
}
