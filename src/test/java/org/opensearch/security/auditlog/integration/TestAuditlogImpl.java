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

package org.opensearch.security.auditlog.integration;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.sink.AuditLogSink;

public class TestAuditlogImpl extends AuditLogSink {

    /** Use the results of `doThenWaitForMessages(...)` instead */
    @Deprecated
    public static List<AuditMessage> messages = new ArrayList<AuditMessage>(100);
    /** Check messages indvidually instead of searching this string */
    @Deprecated
    public static StringBuffer sb = new StringBuffer();
    private static final AtomicReference<CountDownLatch> countDownRef = new AtomicReference<>();
    private static final AtomicReference<List<AuditMessage>> messagesRef = new AtomicReference<>();

    public TestAuditlogImpl(String name, Settings settings, String settingsPrefix, AuditLogSink fallbackSink) {
        super(name, settings, null, fallbackSink);
    }

    public synchronized boolean doStore(AuditMessage msg) {
        if (messagesRef.get() == null || countDownRef.get() == null) {
            throw new RuntimeException("No message latch is waiting");
        }
        sb.append(msg.toPrettyString()+System.lineSeparator());
        messagesRef.get().add(msg);
        countDownRef.get().countDown();
        return true;
    }

    /** Unneeded after switching to `doThenWaitForMessages(...)` as data is automatically flushed */
    @Deprecated
    public static synchronized void clear() {
        doThenWaitForMessages(() -> {}, 0);
    }

    /**
     * Perform an action and then wait until the expected number of messages have been found.
     */
    public static List<AuditMessage> doThenWaitForMessages(final Runnable action, final int expectedCount) {
        final CountDownLatch latch = new CountDownLatch(expectedCount);
        final List<AuditMessage> messages = new ArrayList<>();
        countDownRef.set(latch);
        messagesRef.set(messages);

        TestAuditlogImpl.sb = new StringBuffer();
        TestAuditlogImpl.messages = messages; 
        
        try {
            action.run();
            final int maxSecondsToWaitForMessages = 1; 
            final boolean foundAll = latch.await(maxSecondsToWaitForMessages, TimeUnit.SECONDS);
            if (!foundAll) {
                throw new RuntimeException("Did not recieve all " + expectedCount +" audit messages after a short wait.");
            }
            if (messages.size() != expectedCount) {
                throw new RuntimeException("Unexpected number of messages, was expecting " + expectedCount + ", recieved " + messages.size());
            }
        } catch (final InterruptedException e) {
            throw new RuntimeException("Unexpected exception", e);
        }
        return new ArrayList<>(messages);
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }


}
