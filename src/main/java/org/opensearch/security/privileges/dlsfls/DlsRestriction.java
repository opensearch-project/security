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

import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import com.google.common.collect.ImmutableList;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.join.BitSetProducer;
import org.apache.lucene.search.join.ToChildBlockJoinQuery;

import org.opensearch.common.lucene.search.Queries;
import org.opensearch.index.query.ParsedQuery;
import org.opensearch.index.query.QueryShardContext;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.security.queries.QueryBuilderTraverser;

/**
 * Represents the DlsRestriction for a particular index. Internally, the DLS restriction is realized by boolean queries,
 * which restrict the allowed documents.
 */
public class DlsRestriction extends AbstractRuleBasedPrivileges.Rule {

    public static final DlsRestriction NONE = new DlsRestriction(Collections.emptyList());
    public static final DlsRestriction FULL = new DlsRestriction(ImmutableList.of(DocumentPrivileges.RenderedDlsQuery.MATCH_NONE));

    private final ImmutableList<DocumentPrivileges.RenderedDlsQuery> queries;

    public DlsRestriction(List<DocumentPrivileges.RenderedDlsQuery> queries) {
        this.queries = ImmutableList.copyOf(queries);
    }

    @Override
    public boolean isUnrestricted() {
        return this.queries.isEmpty();
    }

    public org.apache.lucene.search.BooleanQuery.Builder toBooleanQueryBuilder(
        QueryShardContext queryShardContext,
        Function<Query, Query> queryMapFunction
    ) {
        if (this.queries.isEmpty()) {
            return null;
        }

        boolean hasNestedMapping = queryShardContext.getMapperService().hasNested();

        org.apache.lucene.search.BooleanQuery.Builder dlsQueryBuilder = new org.apache.lucene.search.BooleanQuery.Builder();
        dlsQueryBuilder.setMinimumNumberShouldMatch(1);

        for (DocumentPrivileges.RenderedDlsQuery query : this.queries) {
            ParsedQuery parsedQuery = queryShardContext.toQuery(query.getQueryBuilder());
            org.apache.lucene.search.Query luceneQuery = parsedQuery.query();

            if (queryMapFunction != null) {
                luceneQuery = queryMapFunction.apply(luceneQuery);
            }

            dlsQueryBuilder.add(luceneQuery, BooleanClause.Occur.SHOULD);

            if (hasNestedMapping) {
                // Also allow the nested documents of allowed parent documents. Nested documents are
                // recognized the same way as in OpenSearch core, which works for all index versions.
                final Query nonNestedQuery = Queries.newNonNestedFilter();
                final BitSetProducer parentDocumentsFilter = queryShardContext.bitsetFilter(nonNestedQuery);
                // ToChildBlockJoinQuery fails if the parent query matches nested documents
                final Query parentQuery = new BooleanQuery.Builder().add(luceneQuery, BooleanClause.Occur.MUST)
                    .add(nonNestedQuery, BooleanClause.Occur.FILTER)
                    .build();
                dlsQueryBuilder.add(new ToChildBlockJoinQuery(parentQuery, parentDocumentsFilter), BooleanClause.Occur.SHOULD);
            }
        }

        return dlsQueryBuilder;
    }

    public boolean containsTermLookupQuery() {
        for (DocumentPrivileges.RenderedDlsQuery query : this.queries) {
            if (QueryBuilderTraverser.exists(
                query.getQueryBuilder(),
                (q) -> (q instanceof TermsQueryBuilder) && ((TermsQueryBuilder) q).termsLookup() != null
            )) {
                return true;
            }
        }

        return false;
    }

    @Override
    public String toString() {
        if (isUnrestricted()) {
            return "DLS:<none>";
        } else {
            return "DLS:" + queries;
        }
    }

    public ImmutableList<DocumentPrivileges.RenderedDlsQuery> getQueries() {
        return queries;
    }
}
