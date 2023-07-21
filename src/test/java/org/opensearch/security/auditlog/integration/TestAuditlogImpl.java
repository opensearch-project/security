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
import java.util.stream.Collectors;

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
            // Ignore any messages that are sent before TestAuditlogImpl is waiting.
            return true;
        }
        sb.append(msg.toPrettyString() + System.lineSeparator());
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
        final List<AuditMessage> missedMessages = new ArrayList<>();
        final List<AuditMessage> messages = new ArrayList<>();
        final CountDownLatch latch = resetAuditStorage(expectedCount, messages);

        try {
            action.run();
            final int maxSecondsToWaitForMessages = 1;
            boolean foundAll = false;
            foundAll = latch.await(maxSecondsToWaitForMessages, TimeUnit.SECONDS);
            // After the wait has prevent any new messages from being recieved
            resetAuditStorage(0, missedMessages);
            if (!foundAll || messages.size() != expectedCount) {
                throw new MessagesNotFoundException(expectedCount, messages);
            }
        } catch (final InterruptedException e) {
            throw new RuntimeException("Unexpected exception", e);
        }

        // Do not check for missed messages if no messages were expected
        if (expectedCount != 0) {
            try {
                Thread.sleep(100);
                if (missedMessages.size() != 0) {
                    final String missedMessagesErrorMessage = new StringBuilder().append("Audit messages were missed! ")
                        .append("Found " + (missedMessages.size()) + " messages.")
                        .append("Messages found during this time: \n\n")
                        .append(missedMessages.stream().map(AuditMessage::toString).collect(Collectors.joining("\n")))
                        .toString();

                    throw new RuntimeException(missedMessagesErrorMessage);
                }
            } catch (final Exception e) {
                throw new RuntimeException("Unexpected exception", e);
            }
        }

        // Next usage of this class might be using raw stringbuilder / list so reset before that test might run
        resetAuditStorage(0, new ArrayList<>());
        return new ArrayList<>(messages);
    }

    /**
     * Resets all of the mechanics for fresh messages to be captured
     *
     * @param expectedMessageCount The number of messages before the latch is signalled, indicating all messages have been recieved
     * @param message Where messages will be stored after being recieved
     */
    private static CountDownLatch resetAuditStorage(int expectedMessageCount, List<AuditMessage> messages) {
        final CountDownLatch latch = new CountDownLatch(expectedMessageCount);
        countDownRef.set(latch);
        messagesRef.set(messages);

        TestAuditlogImpl.sb = new StringBuffer();
        TestAuditlogImpl.messages = messages;
        return latch;
    }

    /**
     * Perform an action and then wait until a single message has been found.
     */
    public static AuditMessage doThenWaitForMessage(final Runnable action) {
        return doThenWaitForMessages(action, 1).get(0);
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }

    public static class MessagesNotFoundException extends RuntimeException {
        private final int expectedCount;
        private final int missingCount;
        private final List<AuditMessage> foundMessages;

        public MessagesNotFoundException(final int expectedCount, List<AuditMessage> foundMessages) {
            super(MessagesNotFoundException.createDetailMessage(expectedCount, foundMessages));
            this.expectedCount = expectedCount;
            this.missingCount = expectedCount - foundMessages.size();
            this.foundMessages = foundMessages;
        }

        public int getExpectedCount() {
            return expectedCount;
        }

        public int getMissingCount() {
            return missingCount;
        }

        public List<AuditMessage> getFoundMessages() {
            return foundMessages;
        }

        private static String createDetailMessage(final int expectedCount, final List<AuditMessage> foundMessages) {
            return new StringBuilder().append("Did not receive all " + expectedCount + " audit messages after a short wait. ")
                .append("Missing " + (expectedCount - foundMessages.size()) + " messages.")
                .append("Messages found during this time: \n\n")
                .append(foundMessages.stream().map(AuditMessage::toString).collect(Collectors.joining("\n")))
                .toString();
        }
    }
}
