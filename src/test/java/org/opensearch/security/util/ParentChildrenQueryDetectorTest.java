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

import org.apache.lucene.search.join.ScoreMode;
import org.junit.Test;

import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.join.query.HasChildQueryBuilder;
import org.opensearch.join.query.HasParentQueryBuilder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class ParentChildrenQueryDetectorTest {

    @Test
    public void termQueryShouldNotBeParentChildQuery() {
        TermQueryBuilder query = QueryBuilders.termQuery("field", "value");

        assertThat(ParentChildrenQueryDetector.hasParentOrChildQuery(query), equalTo(false));
    }

    @Test
    public void topLevelHasParentQueryShouldBeDetected() {
        HasParentQueryBuilder query = new HasParentQueryBuilder("my_type", QueryBuilders.termQuery("field", "value"), false);

        assertThat(ParentChildrenQueryDetector.hasParentOrChildQuery(query), equalTo(true));
    }

    @Test
    public void topLevelHasChildQueryShouldBeDetected() {
        HasChildQueryBuilder query = new HasChildQueryBuilder("my_type", QueryBuilders.termQuery("field", "value"), ScoreMode.None);

        assertThat(ParentChildrenQueryDetector.hasParentOrChildQuery(query), equalTo(true));
    }

    @Test
    public void shouldDetectHasParentQueryInsideBooleanQuery() {
        BoolQueryBuilder query = QueryBuilders.boolQuery() //
            .must(new HasParentQueryBuilder("my_type", QueryBuilders.termQuery("field", "value"), false)) //
            .should(QueryBuilders.termQuery("another_field", "another_value"));

        assertThat(ParentChildrenQueryDetector.hasParentOrChildQuery(query), equalTo(true));

    }

}
