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
import java.util.stream.Collectors;

import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.security.auditlog.impl.AuditMessage;

abstract class AuditsFulfillPredicateMatcher extends TypeSafeDiagnosingMatcher<List<AuditMessage>> {

    protected final Predicate<AuditMessage> predicate;

    public AuditsFulfillPredicateMatcher(Predicate<AuditMessage> predicate) {
        this.predicate = predicate;
    }

    protected String auditMessagesToString(List<AuditMessage> audits) {
        return audits.stream().map(AuditMessage::toString).collect(Collectors.joining(",\n"));
    }

    protected long countAuditsWhichMatchPredicate(List<AuditMessage> audits) {
        return audits.stream().filter(predicate).count();
    }

}
