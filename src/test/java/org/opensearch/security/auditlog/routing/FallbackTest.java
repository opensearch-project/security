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

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.helper.FailingSink;
import org.opensearch.security.auditlog.helper.LoggingSink;
import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.sink.AuditLogSink;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class FallbackTest extends AbstractAuditlogiUnitTest {

    @Test
    public void testFallback() throws Exception {
        Settings.Builder settingsBuilder = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/fallback.yml"));

        Settings settings = settingsBuilder.put("path.home", ".")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .build();

        AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);

        AuditMessage msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.MISSING_PRIVILEGES);
        router.route(msg);

        // endpoint 1 is failing, endoint2 and default work
        List<AuditLogSink> sinks = router.categorySinks.get(AuditCategory.MISSING_PRIVILEGES);
        assertThat(sinks.size(), is(3));
        // this sink has failed, message must be logged to fallback sink
        AuditLogSink sink = sinks.get(0);
        assertThat(sink.getName(), is("endpoint1"));
        assertThat(sink.getClass(), is(FailingSink.class));
        sink = sink.getFallbackSink();
        assertThat(sink.getName(), is("fallback"));
        assertThat(sink.getClass(), is(LoggingSink.class));
        LoggingSink loggingSkin = (LoggingSink) sink;
        assertThat(loggingSkin.messages.get(0), is(msg));
        // this sink succeeds
        sink = sinks.get(1);
        assertThat(sink.getName(), is("endpoint2"));
        assertThat(sink.getClass(), is(LoggingSink.class));
        loggingSkin = (LoggingSink) sink;
        assertThat(loggingSkin.messages.get(0), is(msg));
        // default sink also succeeds
        sink = sinks.get(2);
        assertThat(sink.getName(), is("default"));
        assertThat(sink.getClass(), is(LoggingSink.class));
        loggingSkin = (LoggingSink) sink;
        assertThat(loggingSkin.messages.get(0), is(msg));

        // has only one end point which fails
        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.COMPLIANCE_DOC_READ);
        router.route(msg);
        sinks = router.categorySinks.get(AuditCategory.COMPLIANCE_DOC_READ);
        sink = sinks.get(0);
        assertThat(sink.getName(), is("endpoint3"));
        assertThat(sink.getClass(), is(FailingSink.class));
        sink = sink.getFallbackSink();
        assertThat(sink.getName(), is("fallback"));
        assertThat(sink.getClass(), is(LoggingSink.class));
        loggingSkin = (LoggingSink) sink;
        assertThat(loggingSkin.messages.get(0), is(msg));

        // has only default which succeeds
        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.COMPLIANCE_DOC_WRITE);
        router.route(msg);
        sinks = router.categorySinks.get(AuditCategory.COMPLIANCE_DOC_WRITE);
        sink = sinks.get(0);
        assertThat(sink.getName(), is("default"));
        assertThat(sink.getClass(), is(LoggingSink.class));
        loggingSkin = (LoggingSink) sink;
        assertThat(loggingSkin.messages.size(), is(1));
        assertThat(loggingSkin.messages.get(0), is(msg));
        // fallback must be empty
        sink = sink.getFallbackSink();
        assertThat(sink.getName(), is("fallback"));
        assertThat(sink.getClass(), is(LoggingSink.class));
        loggingSkin = (LoggingSink) sink;
        assertThat(loggingSkin.messages.size(), is(0));

        // test non configured categories, must be logged to default only
        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.FAILED_LOGIN);
        router.route(msg);
        Assert.assertNull(router.categorySinks.get(AuditCategory.FAILED_LOGIN));
        loggingSkin = (LoggingSink) router.defaultSink;
        assertThat(loggingSkin.messages.size(), is(1));
        assertThat(loggingSkin.messages.get(0), is(msg));
        // all others must be empty
        assertLoggingSinksEmpty(router);

    }

    private void assertLoggingSinksEmpty(AuditMessageRouter router) {
        // get all sinks
        List<AuditLogSink> allSinks = router.categorySinks.values().stream().flatMap(Collection::stream).collect(Collectors.toList());
        allSinks = allSinks.stream().filter(sink -> (sink instanceof LoggingSink)).collect(Collectors.toList());
        allSinks.removeAll(Collections.singleton(router.defaultSink));
        for (AuditLogSink sink : allSinks) {
            LoggingSink loggingSink = (LoggingSink) sink;
            assertThat(loggingSink.messages.size(), is(0));
        }
    }

}
