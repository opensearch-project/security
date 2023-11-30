/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class AggregationTests extends SingleClusterTest {

    @Test
    public void testBasicAggregations() throws Exception {
        final Settings settings = Settings.builder().build();

        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();
            tc.index(new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("starfleet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(
                new IndexRequest("starfleet_academy").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
            tc.index(
                new IndexRequest("starfleet_library").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
            tc.index(
                new IndexRequest("klingonempire").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
            tc.index(new IndexRequest("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            tc.index(new IndexRequest("spock").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("kirk").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(
                new IndexRequest("role01_role02").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();

            tc.index(new IndexRequest("xyz").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            tc.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        AliasActions.add().indices("starfleet", "starfleet_academy", "starfleet_library").alias("sf")
                    )
                )
                .actionGet();
            tc.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire", "vulcangov").alias("nonsf"))
                )
                .actionGet();
            tc.admin()
                .indices()
                .aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted")))
                .actionGet();
            tc.admin()
                .indices()
                .aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("xyz").alias("alias1")))
                .actionGet();

        }

        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest(
                "_search?pretty",
                "{\"size\":0,\"aggs\":{\"indices\":{\"terms\":{\"field\":\"_index\",\"size\":40}}}}",
                encodeBasicHeader("nagilum", "nagilum")
            )).getStatusCode()
        );
        assertNotContains(res, "*xception*");
        assertNotContains(res, "*erial*");
        assertNotContains(res, "*mpty*");
        assertNotContains(res, "*pendistro_security*");
        assertContains(res, "*vulcangov*");
        assertContains(res, "*starfleet*");
        assertContains(res, "*klingonempire*");
        assertContains(res, "*xyz*");
        assertContains(res, "*role01_role02*");
        assertContains(res, "*\"failed\" : 0*");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest(
                "*/_search?pretty",
                "{\"size\":0,\"aggs\":{\"indices\":{\"terms\":{\"field\":\"_index\",\"size\":40}}}}",
                encodeBasicHeader("nagilum", "nagilum")
            )).getStatusCode()
        );
        assertNotContains(res, "*xception*");
        assertNotContains(res, "*erial*");
        assertNotContains(res, "*mpty*");
        assertNotContains(res, "*pendistro_security*");
        assertContains(res, "*vulcangov*");
        assertContains(res, "*starfleet*");
        assertContains(res, "*klingonempire*");
        assertContains(res, "*xyz*");
        assertContains(res, "*role01_role02*");
        assertContains(res, "*\"failed\" : 0*");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest(
                "_search?pretty",
                "{\"size\":0,\"aggs\":{\"indices\":{\"terms\":{\"field\":\"_index\",\"size\":40}}}}",
                encodeBasicHeader("worf", "worf")
            )).getStatusCode()
        );
        assertNotContains(res, "*xception*");
        assertNotContains(res, "*erial*");
        assertNotContains(res, "*mpty*");
        assertNotContains(res, "*pendistro_security*");
        assertNotContains(res, "*vulcangov*");
        assertNotContains(res, "*kirk*");
        assertContains(res, "*starfleet*");
        assertContains(res, "*public*");
        assertContains(res, "*xyz*");
        assertContains(res, "*\"failed\" : 0*");

        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_search?pretty",
                "{\"size\":0,\"aggs\":{\"myindices\":{\"terms\":{\"field\":\"_index\",\"size\":40}}}}",
                encodeBasicHeader("worf", "worf")
            ).getStatusCode()
        );

    }

}
