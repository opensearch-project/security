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

import org.opensearch.action.support.ReadAccessContext;
import org.opensearch.action.support.ReadAccessPolicy;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchNoneQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ReadAccessPolicyProviderImplTest {

    @Test
    public void returnsUnrestrictedPolicyForSystemContext() {
        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);
        ReadAccessPolicyProviderImpl provider = new ReadAccessPolicyProviderImpl(baseContext);

        assertThat(provider.getReadAccessPolicy(context("logs")), sameInstance(ReadAccessPolicy.unrestricted()));
    }

    @Test
    public void returnsMatchNoneForFullyRestrictedIndex() throws Exception {
        DlsFlsBaseContext baseContext = baseContext(DlsRestriction.FULL, "logs");
        ReadAccessPolicyProviderImpl provider = new ReadAccessPolicyProviderImpl(baseContext);

        QueryBuilder query = provider.getReadAccessPolicy(context("logs")).restrictionsForIndex("logs").orElseThrow();

        assertThat(query, instanceOf(MatchNoneQueryBuilder.class));
    }

    @Test
    public void combinesRoleQueriesWithShould() throws Exception {
        QueryBuilder first = QueryBuilders.termQuery("tenant", "blue");
        QueryBuilder second = QueryBuilders.termQuery("tenant", "green");
        DlsRestriction restriction = new DlsRestriction(
            List.of(
                new DocumentPrivileges.RenderedDlsQuery(first, first.toString()),
                new DocumentPrivileges.RenderedDlsQuery(second, second.toString())
            )
        );
        DlsFlsBaseContext baseContext = baseContext(restriction, "logs");
        ReadAccessPolicyProviderImpl provider = new ReadAccessPolicyProviderImpl(baseContext);

        QueryBuilder query = provider.getReadAccessPolicy(context("logs")).restrictionsForIndex("logs").orElseThrow();

        assertThat(query, instanceOf(BoolQueryBuilder.class));
        BoolQueryBuilder bool = (BoolQueryBuilder) query;
        assertThat(bool.should(), hasSize(2));
        assertThat(bool.minimumShouldMatch(), is("1"));
    }

    @Test
    public void groupsIndicesWithEqualRestrictions() throws Exception {
        QueryBuilder firstQuery = QueryBuilders.termQuery("tenant", "blue");
        QueryBuilder secondQuery = QueryBuilders.termQuery("tenant", "blue");
        DlsRestriction firstRestriction = new DlsRestriction(
            List.of(new DocumentPrivileges.RenderedDlsQuery(firstQuery, firstQuery.toString()))
        );
        DlsRestriction secondRestriction = new DlsRestriction(
            List.of(new DocumentPrivileges.RenderedDlsQuery(secondQuery, secondQuery.toString()))
        );
        DlsFlsBaseContext baseContext = baseContext(Map.of("logs-a", firstRestriction, "logs-b", secondRestriction));

        ReadAccessPolicy policy = new ReadAccessPolicyProviderImpl(baseContext).getReadAccessPolicy(context("logs-a", "logs-b"));

        assertThat(policy.indexGroups(), hasSize(1));
        assertThat(policy.indexGroups().iterator().next().concreteIndices(), is(Set.of("logs-a", "logs-b")));
    }

    private static DlsFlsBaseContext baseContext(DlsRestriction restriction, String... indices) throws Exception {
        Map<String, DlsRestriction> restrictions = new LinkedHashMap<>();
        for (String index : indices) {
            restrictions.put(index, restriction);
        }
        return baseContext(restrictions);
    }

    private static DlsFlsBaseContext baseContext(Map<String, DlsRestriction> restrictions) throws Exception {
        PrivilegesEvaluationContext privilegesContext = mock(PrivilegesEvaluationContext.class);
        DocumentPrivileges documentPrivileges = mock(DocumentPrivileges.class);
        for (Map.Entry<String, DlsRestriction> entry : restrictions.entrySet()) {
            when(documentPrivileges.getRestriction(privilegesContext, entry.getKey())).thenReturn(entry.getValue());
        }
        DlsFlsProcessedConfig config = mock(DlsFlsProcessedConfig.class);
        when(config.getDocumentPrivileges()).thenReturn(documentPrivileges);
        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);
        when(baseContext.getPrivilegesEvaluationContext()).thenReturn(privilegesContext);
        when(baseContext.config()).thenReturn(config);
        return baseContext;
    }

    private static ReadAccessContext context(String... indices) {
        return ReadAccessContext.of(List.of(indices));
    }
}
