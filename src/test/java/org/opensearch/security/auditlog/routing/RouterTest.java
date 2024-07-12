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

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.helper.LoggingSink;
import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.sink.AuditLogSink;
import org.opensearch.security.auditlog.sink.DebugSink;
import org.opensearch.security.auditlog.sink.ExternalOpenSearchSink;
import org.opensearch.security.auditlog.sink.InternalOpenSearchSink;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class RouterTest extends AbstractAuditlogiUnitTest {

    @Test
    public void testValidConfiguration() throws Exception {
        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_valid.yml"))
            .build();
        AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
        // default
        assertThat(router.defaultSink.getName(), is("default"));
        assertThat(router.defaultSink.getClass(), is(ExternalOpenSearchSink.class));
        // test category sinks
        List<AuditLogSink> sinks = router.categorySinks.get(AuditCategory.MISSING_PRIVILEGES);
        Assert.assertNotNull(sinks);
        // 3, since we include default as well
        assertThat(sinks.size(), is(3));
        assertThat(sinks.get(0).getName(), is("endpoint1"));
        assertThat(sinks.get(0).getClass(), is(InternalOpenSearchSink.class));
        assertThat(sinks.get(1).getName(), is("endpoint2"));
        assertThat(sinks.get(1).getClass(), is(ExternalOpenSearchSink.class));
        assertThat(sinks.get(2).getName(), is("default"));
        assertThat(sinks.get(2).getClass(), is(ExternalOpenSearchSink.class));
        sinks = router.categorySinks.get(AuditCategory.COMPLIANCE_DOC_READ);
        // 1, since we do not include default
        assertThat(sinks.size(), is(1));
        assertThat(sinks.get(0).getName(), is("endpoint3"));
        assertThat(sinks.get(0).getClass(), is(DebugSink.class));
    }

    @Test
    public void testMessageRouting() throws Exception {

        Settings.Builder settingsBuilder = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/routing.yml"));

        Settings settings = settingsBuilder.put("path.home", ".")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .build();

        AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
        AuditMessage msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.MISSING_PRIVILEGES);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.MISSING_PRIVILEGES, "endpoint1", "endpoint2", "default");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.COMPLIANCE_DOC_READ);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.COMPLIANCE_DOC_READ, "endpoint3");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.COMPLIANCE_DOC_WRITE);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.COMPLIANCE_DOC_WRITE, "default");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.FAILED_LOGIN);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.FAILED_LOGIN, "default");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.GRANTED_PRIVILEGES);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.GRANTED_PRIVILEGES, "default");

    }

    private void testMessageDeliveredForCategory(
        AuditMessageRouter router,
        AuditMessage msg,
        AuditCategory categoryToCheck,
        String... sinkNames
    ) {
        Map<AuditCategory, List<AuditLogSink>> sinksForCategory = router.categorySinks;
        for (AuditCategory category : AuditCategory.values()) {
            List<AuditLogSink> sinks = sinksForCategory.get(category);
            if (sinks == null) {
                continue;
            }
            if (category.equals(categoryToCheck)) {
                // each sink must contain our message
                for (AuditLogSink sink : sinks) {
                    LoggingSink logSink = (LoggingSink) sink;
                    assertThat(logSink.messages.size(), is(1));
                    assertThat(logSink.messages.get(0), is(msg));
                    Assert.assertTrue(logSink.sb.length() > 0);
                    Assert.assertTrue(Arrays.stream(sinkNames).anyMatch(sink.getName()::equals));
                }
            } else {
                // make sure sinks are empty for all other categories, exclude default
                for (AuditLogSink sink : sinks) {
                    // default is configured for multiple categories, skip
                    if (sink.getName().equals("default")) {
                        continue;
                    }
                    LoggingSink logSink = (LoggingSink) sink;
                    assertThat(logSink.messages.size(), is(0));
                    Assert.assertTrue(logSink.sb.length() == 0);
                }
            }
        }
    }

}
