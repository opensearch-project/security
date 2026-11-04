/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.util;

import org.apache.lucene.search.BooleanClause;

import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;

public final class ParentChildrenQueryDetector implements QueryBuilderVisitor {

    private static final String HAS_PARENT_QUERY_NAME = "has_parent";
    private static final String HAS_CHILD_QUERY_NAME = "has_child";

    private boolean queryPresent = false;

    private ParentChildrenQueryDetector() {
        // Private constructor to prevent instantiation
    }

    public static boolean hasParentOrChildQuery(QueryBuilder queryBuilder) {
        ParentChildrenQueryDetector detector = new ParentChildrenQueryDetector();
        queryBuilder.visit(detector);
        return detector.hasParentOrChildQuery();
    }

    /**
     * Do not call the method directly. Static method {@link #hasParentOrChildQuery} should be used instead.
     * @param queryBuilder is a queryBuilder object which is accepeted by the visitor.
     */
    @Override
    public void accept(QueryBuilder queryBuilder) {
        String queryName = queryBuilder.getWriteableName();
        if (HAS_PARENT_QUERY_NAME.equals(queryName) || HAS_CHILD_QUERY_NAME.equals(queryName)) {
            queryPresent = true;
        }
    }

    @Override
    public QueryBuilderVisitor getChildVisitor(BooleanClause.Occur occur) {
        return this;
    }

    public boolean hasParentOrChildQuery() {
        return queryPresent;
    }
}
