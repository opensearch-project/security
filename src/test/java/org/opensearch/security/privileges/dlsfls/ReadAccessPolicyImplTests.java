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

package org.opensearch.security.privileges.dlsfls;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import org.opensearch.action.support.ReadAccessPolicy;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;

public class ReadAccessPolicyImplTests {

    @Test
    public void groupsIndicesWithSharedRestrictions() {
        QueryBuilder restriction = QueryBuilders.termQuery("tenant", "blue");
        ReadAccessPolicy policy = new ReadAccessPolicyImpl(Map.of(restriction, List.of("logs-2025", "logs-2026")), List.of("public-logs"));

        assertThat(policy.hasRestrictions(), is(true));
        assertThat(policy.coveredConcreteIndices(), is(Set.of("logs-2025", "logs-2026", "public-logs")));
        assertThat(policy.restrictionsForIndex("logs-2025").orElseThrow(), sameInstance(restriction));
        assertThat(policy.restrictionsForIndex("public-logs").isEmpty(), is(true));
        assertThat(policy.indexGroups(), hasSize(2));
    }

    @Test
    public void rejectsOverlappingIndexGroups() {
        QueryBuilder first = QueryBuilders.termQuery("tenant", "blue");
        QueryBuilder second = QueryBuilders.termQuery("tenant", "green");
        Map<QueryBuilder, List<String>> groups = new LinkedHashMap<>();
        groups.put(first, List.of("logs"));
        groups.put(second, List.of("logs"));

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> new ReadAccessPolicyImpl(groups, List.of())
        );

        assertThat(exception.getMessage(), is("Concrete index [logs] occurs in more than one index group"));
    }
}
