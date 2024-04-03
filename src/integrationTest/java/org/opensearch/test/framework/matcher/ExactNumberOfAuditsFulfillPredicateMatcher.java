/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.matcher;

import java.util.List;
import java.util.function.Predicate;

import org.hamcrest.Description;

import org.opensearch.security.auditlog.impl.AuditMessage;

class ExactNumberOfAuditsFulfillPredicateMatcher extends AuditsFulfillPredicateMatcher {

    private final long exactNumberOfAuditMessages;

    public ExactNumberOfAuditsFulfillPredicateMatcher(long exactNumberOfAuditMessages, Predicate<AuditMessage> predicate) {
        super(predicate);
        this.exactNumberOfAuditMessages = exactNumberOfAuditMessages;
    }

    @Override
    protected boolean matchesSafely(List<AuditMessage> audits, Description mismatchDescription) {
        long count = countAuditsWhichMatchPredicate(audits);
        if (exactNumberOfAuditMessages != count) {
            mismatchDescription.appendText(" only ")
                .appendValue(count)
                .appendText(" match predicate. Examined audit logs ")
                .appendText(auditMessagesToString(audits));
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendValue(exactNumberOfAuditMessages).appendText(" audit records should match predicate ").appendValue(predicate);
    }
}
