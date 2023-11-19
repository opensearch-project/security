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
import org.junit.Ignore;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

@Ignore("subject for manual execution")
public class TracingTests extends SingleClusterTest {

    @Test
    public void testAdvancedMapping() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true, ClusterConfiguration.DEFAULT);

        try (Client tc = getClient()) {
            tc.admin()
                .indices()
                .create(new CreateIndexRequest("myindex1").mapping(FileHelper.loadFile("mapping1.json"), XContentType.JSON))
                .actionGet();
            tc.admin()
                .indices()
                .create(new CreateIndexRequest("myindex2").mapping(FileHelper.loadFile("mapping2.json"), XContentType.JSON))
                .actionGet();
            tc.admin()
                .indices()
                .create(new CreateIndexRequest("myindex3").mapping(FileHelper.loadFile("mapping3.json"), XContentType.JSON))
                .actionGet();
            tc.admin()
                .indices()
                .create(new CreateIndexRequest("myindex4").mapping(FileHelper.loadFile("mapping4.json"), XContentType.JSON))
                .actionGet();
        }

        RestHelper rh = nonSslRestHelper();
        // write into mapping 1
        String data1 = FileHelper.loadFile("data1.json");
        rh.executePutRequest("myindex1/_doc/1?refresh", data1, encodeBasicHeader("nagilum", "nagilum"));
        rh.executePutRequest("myindex1/_doc/1?refresh", data1, encodeBasicHeader("nagilum", "nagilum"));

        // write into mapping 2");
        rh.executePutRequest("myindex2/_doc/2?refresh", data1, encodeBasicHeader("nagilum", "nagilum"));
        rh.executePutRequest("myindex2/_doc/2?refresh", data1, encodeBasicHeader("nagilum", "nagilum"));

        // write into mapping 3
        String parent = FileHelper.loadFile("data2.json");
        String child = FileHelper.loadFile("data3.json");
        rh.executePutRequest("myindex3/_doc/1?refresh", parent, encodeBasicHeader("nagilum", "nagilum"));
        rh.executePutRequest("myindex3/_doc/2?routing=1&refresh", child, encodeBasicHeader("nagilum", "nagilum"));

        // write into mapping 4
        rh.executePutRequest("myindex4/_doc/1?refresh", parent, encodeBasicHeader("nagilum", "nagilum"));
        rh.executePutRequest("myindex4/_doc/2?routing=1&refresh", child, encodeBasicHeader("nagilum", "nagilum"));
    }

    @Test
    public void testHTTPTraceNoSource() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true, ClusterConfiguration.DEFAULT);

        try (Client tc = getClient()) {
            tc.admin().indices().create(new CreateIndexRequest("a")).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("c")).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("test")).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("u")).actionGet();

            tc.admin()
                .indices()
                .putMapping(
                    new PutMappingRequest("a").source(
                        "_source",
                        "enabled=false",
                        "content",
                        "store=true,type=text",
                        "field1",
                        "store=true,type=text",
                        "field2",
                        "store=true,type=text",
                        "a",
                        "store=true,type=text",
                        "b",
                        "store=true,type=text",
                        "my.nested.field",
                        "store=true,type=text"
                    )
                )
                .actionGet();

            tc.admin()
                .indices()
                .putMapping(
                    new PutMappingRequest("c").source(
                        "_source",
                        "enabled=false",
                        "content",
                        "store=true,type=text",
                        "field1",
                        "store=true,type=text",
                        "field2",
                        "store=true,type=text",
                        "a",
                        "store=true,type=text",
                        "b",
                        "store=true,type=text",
                        "my.nested.field",
                        "store=true,type=text"
                    )
                )
                .actionGet();

            tc.admin()
                .indices()
                .putMapping(
                    new PutMappingRequest("test").source(
                        "_source",
                        "enabled=false",
                        "content",
                        "store=true,type=text",
                        "field1",
                        "store=true,type=text",
                        "field2",
                        "store=true,type=text",
                        "a",
                        "store=true,type=text",
                        "b",
                        "store=true,type=text",
                        "my.nested.field",
                        "store=true,type=text"
                    )
                )
                .actionGet();

            tc.admin()
                .indices()
                .putMapping(
                    new PutMappingRequest("u").source(
                        "_source",
                        "enabled=false",
                        "content",
                        "store=true,type=text",
                        "field1",
                        "store=true,type=text",
                        "field2",
                        "store=true,type=text",
                        "a",
                        "store=true,type=text",
                        "b",
                        "store=true,type=text",
                        "my.nested.field",
                        "store=true,type=text"
                    )
                )
                .actionGet();

            for (int i = 0; i < 50; i++) {
                tc.index(
                    new IndexRequest("a").id(i + "")
                        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                        .source("{\"content\":" + i + "}", XContentType.JSON)
                ).actionGet();
                tc.index(
                    new IndexRequest("c").id(i + "")
                        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                        .source("{\"content\":" + i + "}", XContentType.JSON)
                ).actionGet();
            }
        }

        // setup complex mapping with parent child and nested fields

        RestHelper rh = nonSslRestHelper();
        // check shards
        rh.executeGetRequest("_cat/shards?v", encodeBasicHeader("nagilum", "nagilum"));

        // _bulk
        String bulkBody = "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value1\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator();

        rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum"));

        // _bulk
        bulkBody = "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value1\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator();

        rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum"));

        // cat indices
        // cluster:monitor/state
        // cluster:monitor/health
        // indices:monitor/stats
        rh.executeGetRequest("_cat/indices", encodeBasicHeader("nagilum", "nagilum"));

        // _search
        // indices:data/read/search
        rh.executeGetRequest("_search", encodeBasicHeader("nagilum", "nagilum"));

        // get 1
        // indices:data/read/get
        rh.executeGetRequest("a/b/1", encodeBasicHeader("nagilum", "nagilum"));
        // get 5
        rh.executeGetRequest("a/b/5", encodeBasicHeader("nagilum", "nagilum"));
        // get 17
        rh.executeGetRequest("a/b/17", encodeBasicHeader("nagilum", "nagilum"));

        // index (+create index)
        // indices:data/write/index
        // indices:data/write/bulk
        // indices:admin/create
        // indices:data/write/bulk[s]
        rh.executePostRequest("u/b/1?refresh=true", "{}", encodeBasicHeader("nagilum", "nagilum"));

        // index only
        // indices:data/write/index
        // indices:data/write/bulk
        // indices:admin/create
        // indices:data/write/bulk[s]
        rh.executePostRequest("u/b/2?refresh=true", "{}", encodeBasicHeader("nagilum", "nagilum"));

        // delete
        // indices:data/write/index
        // indices:data/write/bulk
        // indices:admin/create
        // indices:data/write/bulk[s]
        rh.executeDeleteRequest("u/b/2?refresh=true", encodeBasicHeader("nagilum", "nagilum"));

        // msearch
        String msearchBody = "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"public\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();

        rh.executePostRequest("_msearch", msearchBody, encodeBasicHeader("nagilum", "nagilum"));

        // mget
        String mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"a\","
            + "\"_id\" : \"1\""
            + " },"
            + " {"
            + "\"_index\" : \"a\","
            + " \"_id\" : \"12\""
            + "},"
            + " {"
            + "\"_index\" : \"a\","
            + " \"_id\" : \"13\""
            + "},"
            + " {"
            + "\"_index\" : \"a\","
            + " \"_id\" : \"14\""
            + "}"
            + "]"
            + "}";

        rh.executePostRequest("_mget?refresh=true", mgetBody, encodeBasicHeader("nagilum", "nagilum"));

        // delete by query
        String dbqBody = "{" + "" + "  \"query\": { " + "    \"match\": {" + "      \"content\": 12" + "    }" + "  }" + "}";

        rh.executePostRequest("a/b/_delete_by_query", dbqBody, encodeBasicHeader("nagilum", "nagilum"));

        Thread.sleep(5000);
    }

    @Test
    public void testHTTPSingle() throws Exception {
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS + ".worf", "knuddel", "nonexists")
            .build();
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

        }

        // pause1
        Thread.sleep(5000);
        // end pause1

        // search
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_search", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // search done

        // pause2
        Thread.sleep(5000);
        // end pause2

        // _bulk
        String bulkBody = "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value1\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"myindex\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value1\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"myindex\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value1\" }"
            + System.lineSeparator();

        rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum")).getBody();
        // _end
        Thread.sleep(5000);
    }

    @Test
    public void testSearchScroll() throws Exception {
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS + ".worf", "knuddel", "nonexists")
            .build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            for (int i = 0; i < 3; i++)
                tc.index(
                    new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
                ).actionGet();
        }

        // search
        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode()
        );

        int start = res.getBody().indexOf("_scroll_id") + 15;
        String scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start + 1));
        // search scroll
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest(
                "/_search/scroll?pretty=true",
                "{\"scroll_id\" : \"" + scrollid + "\"}",
                encodeBasicHeader("nagilum", "nagilum")
            )).getStatusCode()
        );
        // search done
    }

    @Test
    public void testHTTPTrace() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true, ClusterConfiguration.DEFAULT);

        try (Client tc = getClient()) {

            for (int i = 0; i < 50; i++) {
                tc.index(
                    new IndexRequest("a").id(i + "")
                        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                        .source("{\"content\":" + i + "}", XContentType.JSON)
                ).actionGet();
                tc.index(
                    new IndexRequest("c").id(i + "")
                        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                        .source("{\"content\":" + i + "}", XContentType.JSON)
                ).actionGet();
            }
        }

        RestHelper rh = nonSslRestHelper();
        // check shards
        rh.executeGetRequest("_cat/shards?v", encodeBasicHeader("nagilum", "nagilum"));

        // _bulk
        String bulkBody = "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value1\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator();

        rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum"));

        // _bulk
        bulkBody = "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value1\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            + "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"2\" } }"
            + System.lineSeparator();

        rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum"));

        // cat indices
        // cluster:monitor/state
        // cluster:monitor/health
        // indices:monitor/stats
        rh.executeGetRequest("_cat/indices", encodeBasicHeader("nagilum", "nagilum"));

        // _search
        // indices:data/read/search
        rh.executeGetRequest("_search", encodeBasicHeader("nagilum", "nagilum"));

        // get 1
        // indices:data/read/get
        rh.executeGetRequest("a/b/1", encodeBasicHeader("nagilum", "nagilum"));
        // get 5
        rh.executeGetRequest("a/b/5", encodeBasicHeader("nagilum", "nagilum"));
        // get 17
        rh.executeGetRequest("a/b/17", encodeBasicHeader("nagilum", "nagilum"));

        // index (+create index)
        // indices:data/write/index
        // indices:data/write/bulk
        // indices:admin/create
        // indices:data/write/bulk[s]
        rh.executePostRequest("u/b/1?refresh=true", "{}", encodeBasicHeader("nagilum", "nagilum"));

        // index only
        // indices:data/write/index
        // indices:data/write/bulk
        // indices:admin/create
        // indices:data/write/bulk[s]
        // rh.executePostRequest("u/b/2?refresh=true", "{}", encodeBasicHeader("nagilum", "nagilum"));

        // update
        // indices:data/write/index
        // indices:data/write/bulk
        // indices:admin/create
        // indices:data/write/bulk[s]
        rh.executePostRequest("u/b/2/_update?refresh=true", "{\"doc\" : {\"a\":1}}", encodeBasicHeader("nagilum", "nagilum"));
        // update2
        // indices:data/write/index
        // indices:data/write/bulk
        // indices:admin/create
        // indices:data/write/bulk[s]
        rh.executePostRequest("u/b/2/_update?refresh=true", "{\"doc\" : {\"a\":44, \"b\":55}}", encodeBasicHeader("nagilum", "nagilum"));

        // update3
        // indices:data/write/index
        // indices:data/write/bulk
        // indices:admin/create
        // indices:data/write/bulk[s]
        rh.executePostRequest("u/b/2/_update?refresh=true", "{\"doc\" : {\"b\":66}}", encodeBasicHeader("nagilum", "nagilum"));

        // delete
        // indices:data/write/index
        // indices:data/write/bulk
        // indices:admin/create
        // indices:data/write/bulk[s]
        rh.executeDeleteRequest("u/b/2?refresh=true", encodeBasicHeader("nagilum", "nagilum"));

        // reindex
        String reindex = "{"
            + "  \"source\": {"
            + "    \"index\": \"a\""
            + "  },"
            + "  \"dest\": {"
            + "    \"index\": \"new_a\""
            + "  }"
            + "}";

        rh.executePostRequest("_reindex", reindex, encodeBasicHeader("nagilum", "nagilum"));

        // msearch
        String msearchBody = "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"public\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();

        rh.executePostRequest("_msearch", msearchBody, encodeBasicHeader("nagilum", "nagilum"));

        // mget
        String mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"a\","
            + "\"_id\" : \"1\""
            + " },"
            + " {"
            + "\"_index\" : \"a\","
            + " \"_id\" : \"12\""
            + "},"
            + " {"
            + "\"_index\" : \"a\","
            + " \"_id\" : \"13\""
            + "},"
            + " {"
            + "\"_index\" : \"a\","
            + " \"_id\" : \"14\""
            + "}"
            + "]"
            + "}";

        rh.executePostRequest("_mget?refresh=true", mgetBody, encodeBasicHeader("nagilum", "nagilum"));

        // delete by query
        String dbqBody = "{" + "" + "  \"query\": { " + "    \"match\": {" + "      \"content\": 12" + "    }" + "  }" + "}";

        rh.executePostRequest("a/b/_delete_by_query", dbqBody, encodeBasicHeader("nagilum", "nagilum"));

        Thread.sleep(5000);
    }

}
