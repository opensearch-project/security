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

package org.opensearch.security.auditlog.routing;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.helper.LoggingSink;
import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;

public class PerfTest extends AbstractAuditlogiUnitTest {

    @Test
    @Ignore(value = "jvm crash on cci")
    public void testPerf() throws Exception {
        Settings.Builder settingsBuilder = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/perftest.yml"));

        Settings settings = settingsBuilder.put("path.home", ".")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .build();

        AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
        int limit = 150000;
        while (limit > 0) {
            AuditMessage msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.MISSING_PRIVILEGES);
            router.route(msg);
            limit--;
        }
        LoggingSink loggingSink = (LoggingSink) router.defaultSink.getFallbackSink();
        int currentSize = loggingSink.messages.size();
        Assert.assertTrue(currentSize > 0);
    }

}
