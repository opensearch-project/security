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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security;

import java.lang.Thread.UncaughtExceptionHandler;

import org.apache.http.HttpStatus;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

@Ignore("subject for manual execution")
public class TracingTests extends SingleClusterTest {

    @Test
    public void testAdvancedMapping() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true, ClusterConfiguration.DEFAULT);

        try (TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {
            tc.admin().indices().create(new CreateIndexRequest("myindex1")
            .mapping("mytype1", FileHelper.loadFile("mapping1.json"), XContentType.JSON)).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("myindex2")
            .mapping("mytype2", FileHelper.loadFile("mapping2.json"), XContentType.JSON)).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("myindex3")
            .mapping("mytype3", FileHelper.loadFile("mapping3.json"), XContentType.JSON)).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("myindex4")
            .mapping("mytype4", FileHelper.loadFile("mapping4.json"), XContentType.JSON)).actionGet();
        }

        RestHelper rh = nonSslRestHelper();
        System.out.println("############ write into mapping 1");
        String data1 = FileHelper.loadFile("data1.json");
        System.out.println(rh.executePutRequest("myindex1/mytype1/1?refresh", data1, encodeBasicHeader("nagilum", "nagilum")));
        System.out.println(rh.executePutRequest("myindex1/mytype1/1?refresh", data1, encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ write into mapping 2");
        System.out.println(rh.executePutRequest("myindex2/mytype2/2?refresh", data1, encodeBasicHeader("nagilum", "nagilum")));
        System.out.println(rh.executePutRequest("myindex2/mytype2/2?refresh", data1, encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ write into mapping 3");
        String parent = FileHelper.loadFile("data2.json");
        String child = FileHelper.loadFile("data3.json");
        System.out.println(rh.executePutRequest("myindex3/mytype3/1?refresh", parent, encodeBasicHeader("nagilum", "nagilum")));
        System.out.println(rh.executePutRequest("myindex3/mytype3/2?routing=1&refresh", child, encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ write into mapping 4");
        System.out.println(rh.executePutRequest("myindex4/mytype4/1?refresh", parent, encodeBasicHeader("nagilum", "nagilum")));
        System.out.println(rh.executePutRequest("myindex4/mytype4/2?routing=1&refresh", child, encodeBasicHeader("nagilum", "nagilum")));
    }

    @Test
    public void testHTTPTraceNoSource() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true, ClusterConfiguration.DEFAULT);

        try (TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {
            tc.admin().indices().create(new CreateIndexRequest("a")).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("c")).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("test")).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("u")).actionGet();

            tc.admin().indices().putMapping(new PutMappingRequest("a").type("b")
                                              .source("_source","enabled=false","content","store=true,type=text","field1","store=true,type=text", "field2","store=true,type=text", "a","store=true,type=text", "b","store=true,type=text", "my.nested.field","store=true,type=text")
                                              ).actionGet();

            tc.admin().indices().putMapping(new PutMappingRequest("c").type("d")
            .source("_source","enabled=false","content","store=true,type=text","field1","store=true,type=text", "field2","store=true,type=text", "a","store=true,type=text", "b","store=true,type=text", "my.nested.field","store=true,type=text")
            ).actionGet();

            tc.admin().indices().putMapping(new PutMappingRequest("test").type("type1")
            .source("_source","enabled=false","content","store=true,type=text","field1","store=true,type=text", "field2","store=true,type=text", "a","store=true,type=text", "b","store=true,type=text", "my.nested.field","store=true,type=text")
            ).actionGet();

            tc.admin().indices().putMapping(new PutMappingRequest("u").type("b")
            .source("_source","enabled=false","content","store=true,type=text","field1","store=true,type=text", "field2","store=true,type=text", "a","store=true,type=text", "b","store=true,type=text", "my.nested.field","store=true,type=text")
            ).actionGet();

            for(int i=0; i<50;i++) {
                tc.index(new IndexRequest("a").type("b").id(i+"").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":"+i+"}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("c").type("d").id(i+"").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":"+i+"}", XContentType.JSON)).actionGet();
            }
        }

        //setup complex mapping with parent child and nested fields


        RestHelper rh = nonSslRestHelper();
        System.out.println("############ check shards");
        System.out.println(rh.executeGetRequest("_cat/shards?v", encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ _bulk");
        String bulkBody =
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator();

        System.out.println(rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ _bulk");
        bulkBody =
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator();

        System.out.println(rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum")));


        System.out.println("############ cat indices");
        //cluster:monitor/state
        //cluster:monitor/health
        //indices:monitor/stats
        System.out.println(rh.executeGetRequest("_cat/indices", encodeBasicHeader("nagilum", "nagilum")));


        System.out.println("############ _search");
        //indices:data/read/search
        System.out.println(rh.executeGetRequest("_search", encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ get 1");
        //indices:data/read/get
        System.out.println(rh.executeGetRequest("a/b/1", encodeBasicHeader("nagilum", "nagilum")));
        System.out.println("############ get 5");
        System.out.println(rh.executeGetRequest("a/b/5", encodeBasicHeader("nagilum", "nagilum")));
        System.out.println("############ get 17");
        System.out.println(rh.executeGetRequest("a/b/17", encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ index (+create index)");
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        System.out.println(rh.executePostRequest("u/b/1?refresh=true", "{}",encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ index only");
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        System.out.println(rh.executePostRequest("u/b/2?refresh=true", "{}",encodeBasicHeader("nagilum", "nagilum")));


        System.out.println("############ delete");
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        System.out.println(rh.executeDeleteRequest("u/b/2?refresh=true",encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ msearch");
        String msearchBody =
                "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"public\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();


        System.out.println(rh.executePostRequest("_msearch", msearchBody, encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ mget");
        String mgetBody = "{"+
                "\"docs\" : ["+
                    "{"+
                         "\"_index\" : \"a\","+
                        "\"_type\" : \"b\","+
                        "\"_id\" : \"1\""+
                   " },"+
                   " {"+
                       "\"_index\" : \"a\","+
                       " \"_type\" : \"b\","+
                       " \"_id\" : \"12\""+
                    "},"+
                    " {"+
                    "\"_index\" : \"a\","+
                    " \"_type\" : \"b\","+
                    " \"_id\" : \"13\""+
                 "},"+" {"+
                 "\"_index\" : \"a\","+
                 " \"_type\" : \"b\","+
                 " \"_id\" : \"14\""+
              "}"+
                "]"+
            "}";

        System.out.println(rh.executePostRequest("_mget?refresh=true", mgetBody, encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ delete by query");
        String dbqBody = "{"+
        ""+
        "  \"query\": { "+
        "    \"match\": {"+
        "      \"content\": 12"+
        "    }"+
        "  }"+
        "}";

        System.out.println(rh.executePostRequest("a/b/_delete_by_query", dbqBody, encodeBasicHeader("nagilum", "nagilum")));

        Thread.sleep(5000);
    }

    @Test
    public void testHTTPSingle() throws Exception {

        Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler() {

            @Override
            public void uncaughtException(Thread t, Throwable e) {
                e.printStackTrace();

            }
        });

    final Settings settings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".worf", "knuddel","nonexists")
            .build();
    setup(settings);
    final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.index(new IndexRequest("spock").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("kirk").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("role01_role02").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();

        }

        System.out.println("########pause1");
        Thread.sleep(5000);
        System.out.println("########end pause1");

        System.out.println("########search");
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_search", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        System.out.println("########search done");

        System.out.println("########pause2");
        Thread.sleep(5000);
        System.out.println("########end pause2");

        System.out.println("############ _bulk");
        String bulkBody =
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"myindex\", \"_type\" : \"myindex\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"myindex\", \"_type\" : \"myindex\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator();

        System.out.println(rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum")).getBody());
        System.out.println("############ _end");
        Thread.sleep(5000);
    }

    @Test
    public void testSearchScroll() throws Exception {

        Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler() {

            @Override
            public void uncaughtException(Thread t, Throwable e) {
                e.printStackTrace();

            }
        });

    final Settings settings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".worf", "knuddel","nonexists")
            .build();
    setup(settings);
    final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            for(int i=0; i<3; i++)
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
        }


        System.out.println("########search");
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());

        System.out.println(res.getBody());
        int start = res.getBody().indexOf("_scroll_id") + 15;
        String scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start+1));
        System.out.println(scrollid);
        System.out.println("########search scroll");
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executePostRequest("/_search/scroll?pretty=true", "{\"scroll_id\" : \""+scrollid+"\"}", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());


        System.out.println("########search done");


    }

    @Test
    public void testHTTPTrace() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true, ClusterConfiguration.DEFAULT);

        try (TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {

            for(int i=0; i<50;i++) {
                tc.index(new IndexRequest("a").type("b").id(i+"").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":"+i+"}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("c").type("d").id(i+"").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":"+i+"}", XContentType.JSON)).actionGet();
            }
        }




        RestHelper rh = nonSslRestHelper();
        System.out.println("############ check shards");
        System.out.println(rh.executeGetRequest("_cat/shards?v", encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ _bulk");
        String bulkBody =
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator();

        System.out.println(rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ _bulk");
        bulkBody =
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator();

        System.out.println(rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum")));


        System.out.println("############ cat indices");
        //cluster:monitor/state
        //cluster:monitor/health
        //indices:monitor/stats
        System.out.println(rh.executeGetRequest("_cat/indices", encodeBasicHeader("nagilum", "nagilum")));


        System.out.println("############ _search");
        //indices:data/read/search
        System.out.println(rh.executeGetRequest("_search", encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ get 1");
        //indices:data/read/get
        System.out.println(rh.executeGetRequest("a/b/1", encodeBasicHeader("nagilum", "nagilum")));
        System.out.println("############ get 5");
        System.out.println(rh.executeGetRequest("a/b/5", encodeBasicHeader("nagilum", "nagilum")));
        System.out.println("############ get 17");
        System.out.println(rh.executeGetRequest("a/b/17", encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ index (+create index)");
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        System.out.println(rh.executePostRequest("u/b/1?refresh=true", "{}",encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ index only");
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        System.out.println(rh.executePostRequest("u/b/2?refresh=true", "{}",encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ update");
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        System.out.println(rh.executePostRequest("u/b/2/_update?refresh=true", "{\"doc\" : {\"a\":1}}",encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ update2");
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        System.out.println(rh.executePostRequest("u/b/2/_update?refresh=true", "{\"doc\" : {\"a\":44, \"b\":55}}",encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ update3");
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        System.out.println(rh.executePostRequest("u/b/2/_update?refresh=true", "{\"doc\" : {\"b\":66}}",encodeBasicHeader("nagilum", "nagilum")));


        System.out.println("############ delete");
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        System.out.println(rh.executeDeleteRequest("u/b/2?refresh=true",encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ reindex");
        String reindex =
        "{"+
        "  \"source\": {"+
        "    \"index\": \"a\""+
        "  },"+
        "  \"dest\": {"+
        "    \"index\": \"new_a\""+
        "  }"+
        "}";

        System.out.println(rh.executePostRequest("_reindex", reindex, encodeBasicHeader("nagilum", "nagilum")));


        System.out.println("############ msearch");
        String msearchBody =
                "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"public\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();


        System.out.println(rh.executePostRequest("_msearch", msearchBody, encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ mget");
        String mgetBody = "{"+
                "\"docs\" : ["+
                    "{"+
                         "\"_index\" : \"a\","+
                        "\"_type\" : \"b\","+
                        "\"_id\" : \"1\""+
                   " },"+
                   " {"+
                       "\"_index\" : \"a\","+
                       " \"_type\" : \"b\","+
                       " \"_id\" : \"12\""+
                    "},"+
                    " {"+
                    "\"_index\" : \"a\","+
                    " \"_type\" : \"b\","+
                    " \"_id\" : \"13\""+
                 "},"+" {"+
                 "\"_index\" : \"a\","+
                 " \"_type\" : \"b\","+
                 " \"_id\" : \"14\""+
              "}"+
                "]"+
            "}";

        System.out.println(rh.executePostRequest("_mget?refresh=true", mgetBody, encodeBasicHeader("nagilum", "nagilum")));

        System.out.println("############ delete by query");
        String dbqBody = "{"+
        ""+
        "  \"query\": { "+
        "    \"match\": {"+
        "      \"content\": 12"+
        "    }"+
        "  }"+
        "}";

        System.out.println(rh.executePostRequest("a/b/_delete_by_query", dbqBody, encodeBasicHeader("nagilum", "nagilum")));

        Thread.sleep(5000);
    }

}
