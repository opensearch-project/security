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
import org.apache.lucene.index.Term;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.MatchAllDocsQuery;
import org.apache.lucene.search.PrefixQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.join.BitSetProducer;
import org.apache.lucene.search.join.ToChildBlockJoinQuery;

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

    private static final Query NON_NESTED_QUERY;

    static {
        // Moved from
        // https://github.com/opensearch-project/security/blob/main/src/main/java/org/opensearch/security/configuration/DlsQueryParser.java
        // Match all documents but not the nested ones
        // Nested document types start with __
        // https://discuss.elastic.co/t/whats-nested-documents-layout-inside-the-lucene/59944/9
        NON_NESTED_QUERY = new BooleanQuery.Builder().add(new MatchAllDocsQuery(), BooleanClause.Occur.FILTER)
            .add(new PrefixQuery(new Term("_type", "__")), BooleanClause.Occur.MUST_NOT)
            .build();
    }

    private final ImmutableList<DocumentPrivileges.RenderedDlsQuery> queries;

    DlsRestriction(List<DocumentPrivileges.RenderedDlsQuery> queries) {
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
                final BitSetProducer parentDocumentsFilter = queryShardContext.bitsetFilter(NON_NESTED_QUERY);
                dlsQueryBuilder.add(new ToChildBlockJoinQuery(luceneQuery, parentDocumentsFilter), BooleanClause.Occur.SHOULD);
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
