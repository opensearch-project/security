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

package org.opensearch.security.privileges.actionlevel;

import java.util.Set;

import org.junit.Test;

import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.resolver.IndexResolverReplacer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isForbidden;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.missingPrivileges;
import static org.opensearch.security.util.MockPrivilegeEvaluationContextBuilder.ctx;

public class EmptyActionPrivilegesTest {
    final ActionPrivileges subject = ActionPrivileges.EMPTY;

    @Test
    public void hasClusterPrivilege() {
        assertThat(
            subject.hasClusterPrivilege(ctx().get(), "cluster:monitor/nodes/stats"),
            isForbidden(missingPrivileges("cluster:monitor/nodes/stats"))
        );
    }

    @Test
    public void hasAnyClusterPrivilege() {
        assertThat(subject.hasAnyClusterPrivilege(ctx().get(), Set.of("cluster:monitor/nodes/stats")), isForbidden());
    }

    @Test
    public void hasExplicitClusterPrivilege() {
        assertThat(subject.hasExplicitClusterPrivilege(ctx().get(), "cluster:monitor/nodes/stats"), isForbidden());
    }

    @Test
    public void hasIndexPrivilege() {
        PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(
            ctx().get(),
            Set.of("indices:data/write/index"),
            IndexResolverReplacer.Resolved.ofIndex("any_index")
        );
        assertThat(result, isForbidden());
    }

    @Test
    public void hasExplicitIndexPrivilege() {
        PrivilegesEvaluatorResponse result = subject.hasExplicitIndexPrivilege(
            ctx().get(),
            Set.of("indices:data/write/index"),
            IndexResolverReplacer.Resolved.ofIndex("any_index")
        );
        assertThat(result, isForbidden());
    }
}
