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

import org.hamcrest.Matcher;

import org.opensearch.security.auditlog.impl.AuditMessage;

public class AuditMessageMatchers {

    private AuditMessageMatchers() {

    }

    public static Matcher<List<AuditMessage>> exactNumberOfAuditsFulfillPredicate(
        long exactNumberOfAuditMessages,
        Predicate<AuditMessage> predicate
    ) {
        return new ExactNumberOfAuditsFulfillPredicateMatcher(exactNumberOfAuditMessages, predicate);
    }

    public static Matcher<List<AuditMessage>> atLeastCertainNumberOfAuditsFulfillPredicate(
        long minimumNumberOfAudits,
        Predicate<AuditMessage> predicate
    ) {
        return new AtLeastCertainNumberOfAuditsFulfillPredicateMatcher(predicate, minimumNumberOfAudits);
    }
}
