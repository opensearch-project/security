/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auditlog.sink;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests that Log4JSink enriches Log4j MDC with audit event attributes,
 * enabling operators to route audit logs to different destinations based
 * on event category, action, user, or request type using Log4j's native
 * RoutingAppender.
 */
public class Log4JSinkMdcTest {

    private ClusterService clusterService;
    private CapturingAppender capturingAppender;

    @Before
    public void setup() {
        clusterService = mock(ClusterService.class);
        DiscoveryNode node = mock(DiscoveryNode.class);
        when(node.getName()).thenReturn("test-node");
        when(node.getId()).thenReturn("test-node-id");
        when(node.getHostName()).thenReturn("test-host");
        when(clusterService.localNode()).thenReturn(node);
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test-cluster"));

        // Attach a custom appender that captures MDC values during log events
        capturingAppender = new CapturingAppender("CapturingAppender");
        capturingAppender.start();
        org.apache.logging.log4j.core.Logger logger = (org.apache.logging.log4j.core.Logger) LogManager.getLogger("audit");
        logger.addAppender(capturingAppender);
        logger.setLevel(Level.INFO);

        ThreadContext.clearMap();
    }

    @After
    public void cleanup() {
        ThreadContext.clearMap();
        org.apache.logging.log4j.core.Logger logger = (org.apache.logging.log4j.core.Logger) LogManager.getLogger("audit");
        logger.removeAppender(capturingAppender);
        capturingAppender.stop();
    }

    @Test
    public void testMdcContainsCategoryDuringLog() {
        Log4JSink sink = createSink();

        AuditMessage msg = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, null, null);
        msg.addPrivilege("indices:data/write/index");
        msg.addEffectiveUser("admin");
        msg.addRequestType("IndexRequest");

        sink.doStore(msg);

        assertThat(capturingAppender.capturedEvents.size(), greaterThan(0));
        Map<String, String> capturedMdc = capturingAppender.capturedMdcValues.get(0);
        assertThat(capturedMdc.get("audit_category"), equalTo("GRANTED_PRIVILEGES"));
        assertThat(capturedMdc.get("audit_user"), equalTo("admin"));
        assertThat(capturedMdc.get("audit_request_type"), equalTo("IndexRequest"));
    }

    @Test
    public void testMdcActionSanitizedForFilenames() {
        Log4JSink sink = createSink();

        AuditMessage msg = new AuditMessage(AuditCategory.REQUEST_AUDIT, clusterService, null, null);
        msg.addPrivilege("indices:data/write/bulk[s][p]");
        msg.addRequestType("BulkShardRequest");

        sink.doStore(msg);

        Map<String, String> capturedMdc = capturingAppender.capturedMdcValues.get(0);
        // Colons, slashes, brackets replaced with underscores for filename safety
        assertThat(capturedMdc.get("audit_action"), equalTo("indices_data_write_bulk_s__p_"));
    }

    @Test
    public void testMdcNullFieldsDefaultToUnknown() {
        Log4JSink sink = createSink();

        // Message with no privilege, no user, no request type
        AuditMessage msg = new AuditMessage(AuditCategory.SSL_EXCEPTION, clusterService, null, null);

        sink.doStore(msg);

        Map<String, String> capturedMdc = capturingAppender.capturedMdcValues.get(0);
        assertThat(capturedMdc.get("audit_category"), equalTo("SSL_EXCEPTION"));
        assertThat(capturedMdc.get("audit_action"), equalTo("unknown"));
        assertThat(capturedMdc.get("audit_user"), equalTo("unknown"));
        assertThat(capturedMdc.get("audit_request_type"), equalTo("unknown"));
    }

    @Test
    public void testMdcClearedAfterStore() {
        Log4JSink sink = createSink();

        AuditMessage msg = new AuditMessage(AuditCategory.AUTHENTICATED, clusterService, null, null);
        msg.addEffectiveUser("testuser");

        sink.doStore(msg);

        // Our MDC keys must be removed after doStore completes
        assertThat(ThreadContext.get(Log4JSink.MDC_CATEGORY), is((String) null));
        assertThat(ThreadContext.get(Log4JSink.MDC_ACTION), is((String) null));
        assertThat(ThreadContext.get(Log4JSink.MDC_USER), is((String) null));
        assertThat(ThreadContext.get(Log4JSink.MDC_REQUEST_TYPE), is((String) null));
    }

    @Test
    public void testDifferentCategoriesProduceDifferentMdcValues() {
        Log4JSink sink = createSink();

        // First event — GRANTED_PRIVILEGES
        AuditMessage msg1 = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, null, null);
        msg1.addEffectiveUser("admin");
        sink.doStore(msg1);

        // Second event — COMPLIANCE_DOC_WRITE
        AuditMessage msg2 = new AuditMessage(AuditCategory.COMPLIANCE_DOC_WRITE, clusterService, null, null);
        msg2.addEffectiveUser("datawriter");
        sink.doStore(msg2);

        // Verify each event had its own MDC values — enables routing to different files
        assertThat(capturingAppender.capturedMdcValues.get(0).get("audit_category"), equalTo("GRANTED_PRIVILEGES"));
        assertThat(capturingAppender.capturedMdcValues.get(0).get("audit_user"), equalTo("admin"));

        assertThat(capturingAppender.capturedMdcValues.get(1).get("audit_category"), equalTo("COMPLIANCE_DOC_WRITE"));
        assertThat(capturingAppender.capturedMdcValues.get(1).get("audit_user"), equalTo("datawriter"));
    }

    private Log4JSink createSink() {
        Settings settings = Settings.builder()
            .put("plugins.security.audit.config.log4j.logger_name", "audit")
            .put("plugins.security.audit.config.log4j.level", "INFO")
            .put("plugins.security.audit.config.log4j.enable_mdc_routing", true)
            .build();
        return new Log4JSink("test", settings, "plugins.security.audit.config", null);
    }

    @Test
    public void testConcurrentThreadsDoNotLeakMdc() throws Exception {
        Log4JSink sink = createSink();

        // Capture assertion failures from worker threads
        List<Throwable> threadFailures = Collections.synchronizedList(new ArrayList<>());

        // Two threads logging simultaneously — MDC must not bleed between them
        Thread thread1 = new Thread(() -> {
            try {
                AuditMessage msg = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, null, null);
                msg.addEffectiveUser("user-thread-1");
                sink.doStore(msg);
                // Our MDC keys must be cleared on this thread after
                assertThat(ThreadContext.get(Log4JSink.MDC_CATEGORY), is((String) null));
                assertThat(ThreadContext.get(Log4JSink.MDC_USER), is((String) null));
            } catch (Throwable t) {
                threadFailures.add(t);
            }
        });

        Thread thread2 = new Thread(() -> {
            try {
                AuditMessage msg = new AuditMessage(AuditCategory.FAILED_LOGIN, clusterService, null, null);
                msg.addEffectiveUser("user-thread-2");
                sink.doStore(msg);
                assertThat(ThreadContext.get(Log4JSink.MDC_CATEGORY), is((String) null));
                assertThat(ThreadContext.get(Log4JSink.MDC_USER), is((String) null));
            } catch (Throwable t) {
                threadFailures.add(t);
            }
        });

        thread1.start();
        thread2.start();
        thread1.join(5000);
        thread2.join(5000);

        // Propagate any worker-thread assertion failures to the JUnit thread
        assertThat("Worker threads should have no assertion failures: " + threadFailures, threadFailures.size(), equalTo(0));

        // Verify both events were captured with their own distinct MDC values
        assertThat(capturingAppender.capturedMdcValues.size(), greaterThanOrEqualTo(2));
        boolean foundThread1 = false;
        boolean foundThread2 = false;
        for (Map<String, String> mdc : capturingAppender.capturedMdcValues) {
            if ("user-thread-1".equals(mdc.get(Log4JSink.MDC_USER))) {
                assertThat(mdc.get(Log4JSink.MDC_CATEGORY), equalTo("GRANTED_PRIVILEGES"));
                foundThread1 = true;
            }
            if ("user-thread-2".equals(mdc.get(Log4JSink.MDC_USER))) {
                assertThat(mdc.get(Log4JSink.MDC_CATEGORY), equalTo("FAILED_LOGIN"));
                foundThread2 = true;
            }
        }
        assertThat("Thread 1 event captured", foundThread1, is(true));
        assertThat("Thread 2 event captured", foundThread2, is(true));
    }

    @Test
    public void testLongValuesNotTruncated() {
        Log4JSink sink = createSink();

        // Long cert DN — should be stored as-is (no truncation)
        String longDn = "CN=" + "a".repeat(500) + ",OU=very-long-org-unit,O=very-long-org,C=US";
        AuditMessage msg = new AuditMessage(AuditCategory.REQUEST_AUDIT, clusterService, null, null);
        msg.addEffectiveUser(longDn);

        sink.doStore(msg);

        Map<String, String> capturedMdc = capturingAppender.capturedMdcValues.get(0);
        // Value preserved in full — operator decides if length is a problem in their config
        assertThat(capturedMdc.get("audit_user").length(), greaterThan(500));
    }

    @Test
    public void testSpecialCharactersInValues() {
        Log4JSink sink = createSink();

        // Only filesystem-dangerous chars should be sanitized
        AuditMessage msg = new AuditMessage(AuditCategory.REQUEST_AUDIT, clusterService, null, null);
        msg.addPrivilege("indices:data/write/index");
        msg.addEffectiveUser("user=with,commas.and+plus");

        sink.doStore(msg);

        Map<String, String> capturedMdc = capturingAppender.capturedMdcValues.get(0);
        // Colons and slashes → underscores
        assertThat(capturedMdc.get("audit_action"), equalTo("indices_data_write_index"));
        // Commas, equals, dots, plus are filename-safe — left alone
        assertThat(capturedMdc.get("audit_user"), equalTo("user=with,commas.and+plus"));
    }

    @Test
    public void testControlCharactersStrippedFromMdc() {
        Log4JSink sink = createSink();

        // Control characters (\n, \r, \t) could enable log-forging if used in pattern layouts
        AuditMessage msg = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, null, null);
        msg.addEffectiveUser("legit-user\r\nfake-log-entry: injected");
        msg.addPrivilege("indices:data/write\tindex");

        sink.doStore(msg);

        Map<String, String> capturedMdc = capturingAppender.capturedMdcValues.get(0);
        // Control chars replaced with underscores — no log forging possible
        assertThat(capturedMdc.get(Log4JSink.MDC_USER), equalTo("legit-user__fake-log-entry_ injected"));
        assertThat(capturedMdc.get(Log4JSink.MDC_ACTION), equalTo("indices_data_write_index"));
    }

    @Test
    public void testDisabledSinkSkipsMdcEntirely() {
        // Create a sink with a level that won't be enabled (TRACE when logger is INFO)
        Settings settings = Settings.builder()
            .put("plugins.security.audit.config.log4j.logger_name", "audit")
            .put("plugins.security.audit.config.log4j.level", "TRACE")
            .build();
        Log4JSink sink = new Log4JSink("test", settings, "plugins.security.audit.config", null);

        AuditMessage msg = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, null, null);
        msg.addEffectiveUser("should-not-appear");

        sink.doStore(msg);

        // No events captured — sink was disabled
        assertThat(capturingAppender.capturedEvents.size(), equalTo(0));
        // MDC was never touched — our keys should be absent
        assertThat(ThreadContext.get(Log4JSink.MDC_CATEGORY), is((String) null));
        assertThat(ThreadContext.get(Log4JSink.MDC_ACTION), is((String) null));
        assertThat(ThreadContext.get(Log4JSink.MDC_USER), is((String) null));
        assertThat(ThreadContext.get(Log4JSink.MDC_REQUEST_TYPE), is((String) null));
    }

    @Test
    public void testMdcNotSetWhenMdcRoutingDisabled() {
        // Sink is enabled (INFO level matches) but mdc_routing is not enabled (default off)
        Settings settings = Settings.builder()
            .put("plugins.security.audit.config.log4j.logger_name", "audit")
            .put("plugins.security.audit.config.log4j.level", "INFO")
            // enable_mdc_routing intentionally NOT set — defaults to false
            .build();
        Log4JSink sink = new Log4JSink("test", settings, "plugins.security.audit.config", null);

        AuditMessage msg = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, null, null);
        msg.addEffectiveUser("mdc-should-not-appear");
        msg.addPrivilege("indices:data/write/index");

        sink.doStore(msg);

        // Events ARE captured (sink is enabled and logs normally)
        assertThat(capturingAppender.capturedEvents.size(), greaterThan(0));
        // But MDC was never set — routing is disabled
        assertThat(capturingAppender.capturedMdcValues.get(0).get(Log4JSink.MDC_CATEGORY), is((String) null));
        assertThat(capturingAppender.capturedMdcValues.get(0).get(Log4JSink.MDC_USER), is((String) null));
    }

    @Test
    public void testMultipleCallsToDoStoreEachGetFreshMdc() {
        Log4JSink sink = createSink();

        // First call
        AuditMessage msg1 = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, null, null);
        msg1.addEffectiveUser("first-user");
        sink.doStore(msg1);

        // Second call — MDC should reflect the second message, not the first
        AuditMessage msg2 = new AuditMessage(AuditCategory.MISSING_PRIVILEGES, clusterService, null, null);
        msg2.addEffectiveUser("second-user");
        sink.doStore(msg2);

        // Each log event captured its own MDC — no cross-contamination
        assertThat(capturingAppender.capturedMdcValues.get(0).get("audit_user"), equalTo("first-user"));
        assertThat(capturingAppender.capturedMdcValues.get(0).get("audit_category"), equalTo("GRANTED_PRIVILEGES"));
        assertThat(capturingAppender.capturedMdcValues.get(1).get("audit_user"), equalTo("second-user"));
        assertThat(capturingAppender.capturedMdcValues.get(1).get("audit_category"), equalTo("MISSING_PRIVILEGES"));
    }

    @Test
    public void testMdcCleanedUpEvenWhenLoggingThrows() {
        // Attach an appender that throws during append with ignoreExceptions=false
        // so the exception propagates through auditLogger.log() into our doStore code
        org.apache.logging.log4j.core.Logger logger = (org.apache.logging.log4j.core.Logger) LogManager.getLogger("audit");
        AbstractAppender throwingAppender = new AbstractAppender(
            "ThrowingAppender",
            null,
            PatternLayout.createDefaultLayout(),
            false,
            Property.EMPTY_ARRAY
        ) {
            @Override
            public void append(LogEvent event) {
                throw new RuntimeException("Simulated logging failure");
            }
        };
        throwingAppender.start();
        logger.addAppender(throwingAppender);

        try {
            Log4JSink sink = createSink();
            AuditMessage msg = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, null, null);
            msg.addEffectiveUser("exception-test-user");

            // doStore will throw because the appender throws with ignoreExceptions=false
            boolean exceptionCaught = false;
            try {
                sink.doStore(msg);
            } catch (Exception e) {
                exceptionCaught = true;
            }

            // Verify the exception path was actually exercised
            assertThat("Exception from throwing appender should propagate", exceptionCaught, is(true));

            // MDC keys must be removed regardless of what happened during logging
            assertThat(ThreadContext.get(Log4JSink.MDC_CATEGORY), is((String) null));
            assertThat(ThreadContext.get(Log4JSink.MDC_ACTION), is((String) null));
            assertThat(ThreadContext.get(Log4JSink.MDC_USER), is((String) null));
            assertThat(ThreadContext.get(Log4JSink.MDC_REQUEST_TYPE), is((String) null));
        } finally {
            logger.removeAppender(throwingAppender);
            throwingAppender.stop();
        }
    }

    @Test
    public void testMultiChunkMessagesAllShareSameMdc() {
        // When a message is split into multiple chunks, all chunks should have the same MDC
        Settings settings = Settings.builder()
            .put("plugins.security.audit.config.log4j.logger_name", "audit")
            .put("plugins.security.audit.config.log4j.level", "INFO")
            .put("plugins.security.audit.config.log4j.enable_mdc_routing", true)
            .put("plugins.security.audit.config.log4j.maximum_index_characters_per_message", 255)
            .build();
        Log4JSink sink = new Log4JSink("test", settings, "plugins.security.audit.config", null);

        AuditMessage msg = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, null, null);
        msg.addEffectiveUser("multi-chunk-user");
        // Use enough long index names to force a split at 255 chars per message
        msg.addResolvedIndices(new String[] { "a".repeat(255), "b".repeat(255), "c".repeat(255) });

        sink.doStore(msg);

        // Multiple log events should have been produced (split message)
        assertThat("Message should be split into multiple chunks", capturingAppender.capturedMdcValues.size(), greaterThan(1));

        // All chunks share the same MDC values
        for (Map<String, String> mdc : capturingAppender.capturedMdcValues) {
            assertThat(mdc.get(Log4JSink.MDC_CATEGORY), equalTo("GRANTED_PRIVILEGES"));
            assertThat(mdc.get(Log4JSink.MDC_USER), equalTo("multi-chunk-user"));
        }
    }

    /**
     * Custom Log4j appender that captures MDC values at the moment each log event is written.
     * This lets us verify that MDC enrichment is active during the logging call.
     */
    private static class CapturingAppender extends AbstractAppender {
        final List<LogEvent> capturedEvents = Collections.synchronizedList(new ArrayList<>());
        final List<Map<String, String>> capturedMdcValues = Collections.synchronizedList(new ArrayList<>());

        CapturingAppender(String name) {
            super(name, null, PatternLayout.createDefaultLayout(), true, Property.EMPTY_ARRAY);
        }

        @Override
        public void append(LogEvent event) {
            capturedEvents.add(event.toImmutable());
            // Capture MDC snapshot at log time
            capturedMdcValues.add(new ConcurrentHashMap<>(event.getContextData().toMap()));
        }
    }
}
