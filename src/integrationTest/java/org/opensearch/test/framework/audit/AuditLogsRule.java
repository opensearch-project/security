/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.audit;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.awaitility.Awaitility;
import org.awaitility.core.ConditionTimeoutException;
import org.hamcrest.Matcher;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import org.opensearch.security.auditlog.impl.AuditMessage;

import static java.util.Collections.synchronizedList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.opensearch.test.framework.matcher.AuditMessageMatchers.atLeastCertainNumberOfAuditsFulfillPredicate;
import static org.opensearch.test.framework.matcher.AuditMessageMatchers.exactNumberOfAuditsFulfillPredicate;

public class AuditLogsRule implements TestRule {

    private static final Logger log = LogManager.getLogger(AuditLogsRule.class);

    private List<AuditMessage> currentTestAuditMessages;
    private List<AuditMessage> currentTransportTestAuditMessages;

    public List<AuditMessage> getCurrentTestAuditMessages() {
        return currentTestAuditMessages;
    }

    public void waitForAuditLogs() {
        try {
            TimeUnit.SECONDS.sleep(3);
            afterWaitingForAuditLogs();
        } catch (InterruptedException e) {
            throw new RuntimeException("Waiting for audit logs interrupted.", e);
        }
    }

    private void afterWaitingForAuditLogs() {
        if (log.isDebugEnabled()) {
            log.debug("Audit records captured during test:\n{}", auditMessagesToString(currentTestAuditMessages));
            log.debug("Audit transport records captured during test:\n{}", auditMessagesToString(currentTransportTestAuditMessages));
        }
    }

    public void assertExactlyOne(Predicate<AuditMessage> predicate) {
        assertExactly(1, predicate);
    }

    public void assertExactlyScanAll(long expectedNumberOfAuditMessages, Predicate<AuditMessage> predicate) {
        List<AuditMessage> auditMessages = new ArrayList<>(currentTestAuditMessages);
        auditMessages.addAll(currentTransportTestAuditMessages);
        assertExactly(exactNumberOfAuditsFulfillPredicate(expectedNumberOfAuditMessages, predicate), auditMessages);

    }

    public void assertAuditLogsCount(int from, int to) {
        int actualCount = currentTestAuditMessages.size();
        String message = "Expected audit log count is between " + from + " and " + to + " but was " + actualCount;
        assertThat(message, actualCount, allOf(greaterThanOrEqualTo(from), lessThanOrEqualTo(to)));
    }

    public void assertExactly(long expectedNumberOfAuditMessages, Predicate<AuditMessage> predicate) {
        assertExactly(exactNumberOfAuditsFulfillPredicate(expectedNumberOfAuditMessages, predicate), currentTestAuditMessages);
    }

    private void assertExactly(Matcher<List<AuditMessage>> matcher, List<AuditMessage> currentTestAuditMessages) {
        // pollDelay - initial delay before first evaluation
        Awaitility.await("Await for audit logs")
            .atMost(3, TimeUnit.SECONDS)
            .pollDelay(0, TimeUnit.MICROSECONDS)
            .until(() -> new ArrayList<>(currentTestAuditMessages), matcher);
    }

    public void assertAtLeast(long minCount, Predicate<AuditMessage> predicate) {
        assertExactly(atLeastCertainNumberOfAuditsFulfillPredicate(minCount, predicate), currentTestAuditMessages);
    }

    public void assertAtLeastTransportMessages(long minCount, Predicate<AuditMessage> predicate) {
        assertExactly(atLeastCertainNumberOfAuditsFulfillPredicate(minCount, predicate), currentTransportTestAuditMessages);
    }

    private static String auditMessagesToString(List<AuditMessage> audits) {
        return audits.stream().map(AuditMessage::toString).collect(Collectors.joining(",\n"));
    }

    @Override
    public Statement apply(Statement statement, Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                String methodName = description.getMethodName();
                beforeTest(methodName);
                try {
                    statement.evaluate();
                } catch (ConditionTimeoutException ex) {
                    whenTimeoutOccurs(methodName);
                    throw ex;
                } finally {
                    afterTest();
                }
            }
        };
    }

    private void whenTimeoutOccurs(String methodName) {
        List<AuditMessage> copy = new ArrayList<>(currentTestAuditMessages);
        String auditMessages = auditMessagesToString(copy);
        log.error(
            "Timeout occured due to insufficient number ('{}') of captured audit messages during test '{}'\n{}",
            copy.size(),
            methodName,
            auditMessages
        );
    }

    private void afterTest() {
        TestRuleAuditLogSink.unregisterListener();
        this.currentTestAuditMessages = null;
        this.currentTransportTestAuditMessages = null;
    }

    private void beforeTest(String methodName) {
        log.info("Start collecting audit logs before test {}", methodName);
        this.currentTestAuditMessages = synchronizedList(new ArrayList<>());
        this.currentTransportTestAuditMessages = synchronizedList(new ArrayList<>());
        TestRuleAuditLogSink.registerListener(this);
    }

    public void onAuditMessage(AuditMessage auditMessage) {
        if (auditMessage.getAsMap().keySet().contains("audit_transport_headers")) {
            if (log.isDebugEnabled()) {
                log.debug(
                    "New transport audit message received '{}', total number of transport audit messages '{}'.",
                    auditMessage,
                    currentTransportTestAuditMessages.size()
                );
            }
            currentTransportTestAuditMessages.add(auditMessage);
        } else {
            if (log.isDebugEnabled()) {
                log.debug(
                    "New audit message received '{}', total number of audit messages '{}'.",
                    auditMessage,
                    currentTestAuditMessages.size()
                );
            }
            currentTestAuditMessages.add(auditMessage);
        }
    }
}
