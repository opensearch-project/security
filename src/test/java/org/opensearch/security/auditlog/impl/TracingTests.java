/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.auditlog.impl;

import java.lang.Thread.UncaughtExceptionHandler;

import org.opensearch.security.auditlog.AuditTestUtils;

import net.jcip.annotations.NotThreadSafe;
import org.apache.http.HttpStatus;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

@NotThreadSafe
public class TracingTests extends SingleClusterTest {

    @Override
    protected String getResourceFolder() {
        return "auditlog";
    }

    @Test
    public void testHTTPTrace() throws Exception {
        final Settings settings = Settings.builder()
                .put(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, "debug")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, "true")
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, "*")
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "*")
                .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings, true, ClusterConfiguration.DEFAULT);

        RestHelper rh = nonSslRestHelper();
        rh.executePutRequest("_opendistro/_security/api/audit/config", AuditTestUtils.createAuditPayload(settings), encodeBasicHeader("admin", "admin"));

        try (TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {

            for(int i=0; i<50;i++) {
                tc.index(new IndexRequest("a").type("b").id(i+"").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":"+i+"}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("c").type("d").id(i+"").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":"+i+"}", XContentType.JSON)).actionGet();
            }
        }


        rh.executeGetRequest("_cat/shards?v", encodeBasicHeader("admin", "admin"));

        rh.executeGetRequest("_opendistro/_security/authinfo",encodeBasicHeader("admin", "admin"));

        String bulkBody =
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator();

        rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("admin", "admin"));

        bulkBody =
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator();

        rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("admin", "admin"));


        //cluster:monitor/state
        //cluster:monitor/health
        //indices:monitor/stats
        rh.executeGetRequest("_cat/indices", encodeBasicHeader("admin", "admin"));


        //indices:data/read/search
        rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin"));

        //indices:data/read/get
        rh.executeGetRequest("a/b/1", encodeBasicHeader("admin", "admin"));
        rh.executeGetRequest("a/b/5", encodeBasicHeader("admin", "admin"));
        rh.executeGetRequest("a/b/17", encodeBasicHeader("admin", "admin"));

        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        rh.executePostRequest("u/b/1?refresh=true", "{}",encodeBasicHeader("admin", "admin"));

        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        rh.executePostRequest("u/b/2?refresh=true", "{}",encodeBasicHeader("admin", "admin"));

        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        rh.executePostRequest("u/b/2?refresh=true", "{\"n\":1, \"m\":1}",encodeBasicHeader("admin", "admin"));
        rh.executePostRequest("u/b/2?refresh=true", "{\"n\":2, \"m\":1, \"z\":1}",encodeBasicHeader("admin", "admin"));
        rh.executePostRequest("u/b/2?refresh=true", "{\"n\":2, \"z\":4}",encodeBasicHeader("admin", "admin"));
        rh.executePostRequest("u/b/2?refresh=true", "{\"n\":5, \"z\":5}",encodeBasicHeader("admin", "admin"));
        rh.executePostRequest("u/b/2?refresh=true", "{\"n\":5}",encodeBasicHeader("admin", "admin"));
        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        rh.executePostRequest("u/b/2/_update?refresh=true", "{\"doc\" : {\"a\":1}}",encodeBasicHeader("admin", "admin"));

        //indices:data/write/index
        //indices:data/write/bulk
        //indices:admin/create
        //indices:data/write/bulk[s]
        rh.executeDeleteRequest("u/b/2?refresh=true",encodeBasicHeader("admin", "admin"));

        String reindex =
        "{"+
        "  \"source\": {"+
        "    \"index\": \"a\""+
        "  },"+
        "  \"dest\": {"+
        "    \"index\": \"new_a\""+
        "  }"+
        "}";

        rh.executePostRequest("_reindex", reindex, encodeBasicHeader("admin", "admin"));


        String msearchBody =
                "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"a\", \"type\":\"b\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"public\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();


        rh.executePostRequest("_msearch", msearchBody, encodeBasicHeader("admin", "admin"));

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

        rh.executePostRequest("_mget?refresh=true", mgetBody, encodeBasicHeader("admin", "admin"));

        String dbqBody = "{"+
        ""+
        "  \"query\": { "+
        "    \"match\": {"+
        "      \"content\": 12"+
        "    }"+
        "  }"+
        "}";

        rh.executePostRequest("a/b/_delete_by_query", dbqBody, encodeBasicHeader("admin", "admin"));
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
            .putList(ConfigConstants.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".worf", "knuddel","nonexists")
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

        Thread.sleep(5000);

        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin")).getStatusCode());

        Thread.sleep(5000);

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

        rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("admin", "admin")).getBody();
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
            .putList(ConfigConstants.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".worf", "knuddel","nonexists")
            .build();
    setup(settings);
    final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            for(int i=0; i<3; i++)
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
        }


        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("admin", "admin"))).getStatusCode());

        int start = res.getBody().indexOf("_scroll_id") + 15;
        String scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start+1));
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executePostRequest("/_search/scroll?pretty=true", "{\"scroll_id\" : \""+scrollid+"\"}", encodeBasicHeader("admin", "admin"))).getStatusCode());




    }

    @Test
    public void testAdvancedMapping() throws Exception {
        Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, "*")
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "*")
                .put(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, "debug").build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings, true, ClusterConfiguration.DEFAULT);

        RestHelper rh = nonSslRestHelper();
        rh.executePutRequest("_opendistro/_security/api/audit/config", AuditTestUtils.createAuditPayload(settings), encodeBasicHeader("admin", "admin"));

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

        String data1 = FileHelper.loadFile("auditlog/data1.json");
        String data2 = FileHelper.loadFile("auditlog/data1mod.json");
        rh.executePutRequest("myindex1/mytype1/1?refresh", data1, encodeBasicHeader("admin", "admin"));
        rh.executePutRequest("myindex1/mytype1/1?refresh", data1, encodeBasicHeader("admin", "admin"));
        rh.executePutRequest("myindex1/mytype1/1?refresh", data2, encodeBasicHeader("admin", "admin"));

        rh.executePutRequest("myindex2/mytype2/2?refresh", data1, encodeBasicHeader("admin", "admin"));
        rh.executePutRequest("myindex2/mytype2/2?refresh", data2, encodeBasicHeader("admin", "admin"));

        String parent = FileHelper.loadFile("auditlog/data2.json");
        String child = FileHelper.loadFile("auditlog/data3.json");
        rh.executePutRequest("myindex3/mytype3/1?refresh", parent, encodeBasicHeader("admin", "admin"));
        rh.executePutRequest("myindex3/mytype3/2?routing=1&refresh", child, encodeBasicHeader("admin", "admin"));

        rh.executePutRequest("myindex4/mytype4/1?refresh", parent, encodeBasicHeader("admin", "admin"));
        rh.executePutRequest("myindex4/mytype4/2?routing=1&refresh", child, encodeBasicHeader("admin", "admin"));

        rh.executeGetRequest("myindex1/mytype1/1?pretty=true&_source=true&_source_include=*.id&_source_exclude=entities&stored_fields=tags,counter", encodeBasicHeader("admin", "admin")).getBody();

        rh.executeGetRequest("myindex1/_search", encodeBasicHeader("admin", "admin")).getStatusCode();

    }

    @Test
    public void testImmutableIndex() throws Exception {
        Settings settings = Settings.builder()
                .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
                .put(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "myindex1")
                .put(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, "debug").build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings, true, ClusterConfiguration.DEFAULT);

        RestHelper rh = nonSslRestHelper();
        rh.executePutRequest("_opendistro/_security/api/audit/config", AuditTestUtils.createAuditPayload(Settings.EMPTY), encodeBasicHeader("admin", "admin"));

        try (TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {
            tc.admin().indices().create(new CreateIndexRequest("myindex1")
            .mapping("mytype1", FileHelper.loadFile("mapping1.json"), XContentType.JSON)).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("myindex2")
            .mapping("mytype2", FileHelper.loadFile("mapping1.json"), XContentType.JSON)).actionGet();
        }

        String data1 = FileHelper.loadFile("auditlog/data1.json");
        String data2 = FileHelper.loadFile("auditlog/data1mod.json");
        HttpResponse res = rh.executePutRequest("myindex1/mytype1/1?refresh", data1, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(201, res.getStatusCode());
        res = rh.executePutRequest("myindex1/mytype1/1?refresh", data2, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(409, res.getStatusCode());
        res = rh.executeDeleteRequest("myindex1/mytype1/1?refresh", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(403, res.getStatusCode());
        res = rh.executeGetRequest("myindex1/mytype1/1", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(200, res.getStatusCode());
        Assert.assertFalse(res.getBody().contains("city"));
        Assert.assertTrue(res.getBody().contains("\"found\":true,"));

        res = rh.executePutRequest("myindex2/mytype2/1?refresh", data1, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(201, res.getStatusCode());
        res = rh.executePutRequest("myindex2/mytype2/1?refresh", data2, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(200, res.getStatusCode());
        res = rh.executeGetRequest("myindex2/mytype2/1", encodeBasicHeader("admin", "admin"));
        Assert.assertTrue(res.getBody().contains("city"));
        res = rh.executeDeleteRequest("myindex2/mytype2/1?refresh", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(200, res.getStatusCode());
        res = rh.executeGetRequest("myindex2/mytype2/1", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(404, res.getStatusCode());
    }

}
