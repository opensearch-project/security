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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.support.ReadAccessContext;
import org.opensearch.action.support.ReadAccessPolicy;
import org.opensearch.action.support.ReadAccessPolicyProvider;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;

/** Supplies the effective Security DLS restrictions to logical query planners. */
public final class ReadAccessPolicyProviderImpl implements ReadAccessPolicyProvider {

    private final DlsFlsBaseContext baseContext;

    public ReadAccessPolicyProviderImpl(DlsFlsBaseContext baseContext) {
        this.baseContext = baseContext;
    }

    @Override
    public ReadAccessPolicy getReadAccessPolicy(ReadAccessContext context) {
        PrivilegesEvaluationContext privilegesContext = baseContext.getPrivilegesEvaluationContext();
        if (privilegesContext == null) {
            return ReadAccessPolicy.unrestricted();
        }

        try {
            Map<QueryBuilder, Set<String>> indicesByRestriction = new LinkedHashMap<>();
            Set<String> unrestrictedIndices = new LinkedHashSet<>();
            for (String index : context.concreteIndices()) {
                DlsRestriction restriction = baseContext.config().getDocumentPrivileges().getRestriction(privilegesContext, index);
                if (restriction.isUnrestricted()) {
                    unrestrictedIndices.add(index);
                } else {
                    QueryBuilder query = combine(restriction.getQueries());
                    indicesByRestriction.computeIfAbsent(query, ignored -> new LinkedHashSet<>()).add(index);
                }
            }

            return new ReadAccessPolicyImpl(indicesByRestriction, unrestrictedIndices);
        } catch (PrivilegesEvaluationException e) {
            throw new OpenSearchSecurityException("Unable to determine DLS policy", e);
        }
    }

    private static QueryBuilder combine(List<DocumentPrivileges.RenderedDlsQuery> queries) {
        if (queries.size() == 1) {
            return queries.getFirst().getQueryBuilder();
        }
        BoolQueryBuilder combined = new BoolQueryBuilder().minimumShouldMatch(1);
        for (DocumentPrivileges.RenderedDlsQuery query : queries) {
            combined.should(query.getQueryBuilder());
        }
        return combined;
    }
}
