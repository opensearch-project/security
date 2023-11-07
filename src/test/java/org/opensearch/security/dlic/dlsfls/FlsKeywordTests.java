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

package org.opensearch.security.dlic.dlsfls;

import java.util.Arrays;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.StringContains.containsString;

public class FlsKeywordTests extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {
        tc.index(
            new IndexRequest("movies").id("0")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"year\": 2013, \"title\": \"Rush\", \"actors\": [\"Daniel Br\u00FChl\", \"Chris Hemsworth\", \"Olivia Wilde\"]}",
                    XContentType.JSON
                )
        ).actionGet();
    }

    private Header movieUser = encodeBasicHeader("user_aaa", "password");
    private Header movieNoActorUser = encodeBasicHeader("user_bbb", "password");

    private String[] actors = new String[] { "Daniel Br\u00FChl", "Chris Hemsworth", "Olivia Wilde" };

    @Test
    public void testKeywordsAreAutomaticallyFiltered() throws Exception {
        setup(new DynamicSecurityConfig().setSecurityRoles("roles_keyword.yml").setSecurityRolesMapping("roles_mappings_keyword.yml"));

        final String searchQuery = "/movies/_search?filter_path=hits.hits._source";
        final String aggQuery = "/movies/_search?filter_path=aggregations.actors.buckets.key";
        final String aggByActorKeyword = "{\"aggs\":{\"actors\":{\"terms\":{\"field\":\"actors.keyword\",\"size\":10}}}}";

        // At document level, the user should see actors
        final HttpResponse searchMovieUser = rh.executeGetRequest(searchQuery, movieUser);
        assertThat(searchMovieUser.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertActorsPresent(searchMovieUser);

        // In aggregate search, the user should see actors
        final HttpResponse searchAggregateMovieUser = rh.executePostRequest(aggQuery, aggByActorKeyword, movieUser);
        assertThat(searchAggregateMovieUser.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertActorsPresent(searchAggregateMovieUser);

        // At document level, the user should see no actors
        final HttpResponse searchMovieNoActorUser = rh.executeGetRequest(searchQuery, movieNoActorUser);
        assertThat(searchMovieNoActorUser.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertActorsNotPresent(searchMovieNoActorUser);

        // In aggregate search, the user should see no actors
        final HttpResponse searchAggregateMovieNoActorUser = rh.executePostRequest(aggQuery, aggByActorKeyword, movieNoActorUser);
        assertThat(searchAggregateMovieNoActorUser.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertActorsNotPresent(searchAggregateMovieNoActorUser);
    }

    private void assertActorsPresent(final HttpResponse response) {
        Arrays.stream(actors).forEach(actor -> { assertThat(response.getBody(), containsString(actor)); });
    }

    private void assertActorsNotPresent(final HttpResponse response) {
        Arrays.stream(actors).forEach(actor -> { assertThat(response.getBody(), not(containsString(actor))); });
    }
}
