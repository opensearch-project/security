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

package org.opensearch.security.multitenancy.test;

import java.util.HashMap;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.opensearch.action.admin.indices.alias.Alias;
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

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class MultitenancyTests extends SingleClusterTest {

    @Override
    protected String getResourceFolder() {
        return "multitenancy";
    }

    @Test
    public void testNoDnfof() throws Exception {

        final Settings settings = Settings.builder()
                .put(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_nodnfof.yml"), settings);
        final RestHelper rh = nonSslRestHelper();

            try (TransportClient tc = getInternalTransportClient()) {
                tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();

                tc.index(new IndexRequest("indexa").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexa\"}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("indexb").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexb\"}", XContentType.JSON)).actionGet();


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

            HttpResponse resc;
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_b", "user_b"))).getStatusCode());

            String msearchBody =
                    "{\"index\":\"indexa\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                    "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                    "{\"index\":\"indexb\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                    "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();
            resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_a", "user_a"));
            Assert.assertEquals(200, resc.getStatusCode());
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
            Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

            resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
            Assert.assertEquals(200, resc.getStatusCode());
            Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

            msearchBody =
                    "{\"index\":\"indexc\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                    "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                    "{\"index\":\"indexd\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                    "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

            resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
            Assert.assertEquals(200, resc.getStatusCode());
            Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexc"));
            Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexd"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));
            int count = resc.getBody().split("\"status\" : 403").length;
            Assert.assertEquals(3, count);

            String mgetBody = "{"+
                    "\"docs\" : ["+
                        "{"+
                             "\"_index\" : \"indexa\","+
                            "\"_type\" : \"doc\","+
                            "\"_id\" : \"0\""+
                       " },"+
                       " {"+
                           "\"_index\" : \"indexb\","+
                           " \"_type\" : \"doc\","+
                           " \"_id\" : \"0\""+
                        "}"+
                    "]"+
                "}";

            resc = rh.executePostRequest("_mget?pretty",  mgetBody, encodeBasicHeader("user_b", "user_b"));
            Assert.assertEquals(200, resc.getStatusCode());
            Assert.assertFalse(resc.getBody(), resc.getBody().contains("\"content\" : \"indexa\""));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

            mgetBody = "{"+
                    "\"docs\" : ["+
                        "{"+
                             "\"_index\" : \"indexx\","+
                            "\"_type\" : \"doc\","+
                            "\"_id\" : \"0\""+
                       " },"+
                       " {"+
                           "\"_index\" : \"indexy\","+
                           " \"_type\" : \"doc\","+
                           " \"_id\" : \"0\""+
                        "}"+
                    "]"+
                "}";

            resc = rh.executePostRequest("_mget?pretty",  mgetBody, encodeBasicHeader("user_b", "user_b"));
            Assert.assertEquals(200, resc.getStatusCode());
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
            count = resc.getBody().split("root_cause").length;
            Assert.assertEquals(3, count);

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("index*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());


            Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("indexa/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("_all/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("notexists/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

            Assert.assertEquals(HttpStatus.SC_NOT_FOUND, (resc=rh.executeGetRequest("indexanbh,indexabb*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

            Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("worf", "worf"))).getStatusCode());

    }

    @Test
    public void testMt() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        String body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executePutRequest(".kibana/config/5.6.0?pretty",body, new BasicHeader("securitytenant", "blafasel"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());

        body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executePutRequest(".kibana/config/5.6.0?pretty",body, new BasicHeader("securitytenant", "business_intelligence"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());

        body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
        Assert.assertEquals(HttpStatus.SC_CREATED, (res = rh.executePutRequest(".kibana/config/5.6.0?pretty",body, new BasicHeader("securitytenant", "human_resources"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());
        Assert.assertEquals(".kibana_1592542611_humanresources_1", DefaultObjectMapper.readTree(res.getBody()).get("_index").asText());

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/config/5.6.0?pretty",new BasicHeader("securitytenant", "human_resources"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());
        Assert.assertTrue(WildcardMatcher.from("*human_resources*").test(res.getBody()));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana_1592542611_humanresources_1/_alias", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertNotNull(DefaultObjectMapper.readTree(res.getBody()).get(".kibana_1592542611_humanresources_1").get("aliases").get(".kibana_1592542611_humanresources"));

    }


    @Test
    public void testMtMulti() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);

        final String dashboardsIndex = ".kibana_92668751_admin_1";
        try (TransportClient tc = getInternalTransportClient()) {
            String body = "{"+
                    "\"type\" : \"index-pattern\","+
                    "\"updated_at\" : \"2018-09-29T08:56:59.066Z\","+
                    "\"index-pattern\" : {"+
                      "\"title\" : \"humanresources\""+
                     "}}";
            Map indexSettings = new HashMap();
            indexSettings.put("number_of_shards", 1);
            indexSettings.put("number_of_replicas", 0);
            tc.admin().indices().create(new CreateIndexRequest(dashboardsIndex)
                .settings(indexSettings)
                .alias(new Alias(".kibana_92668751_admin")))
                .actionGet();

            tc.index(new IndexRequest(dashboardsIndex).type("doc")
                    .id("index-pattern:9fbbd1a0-c3c5-11e8-a13f-71b8ea5a4f7b")
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(body, XContentType.JSON)).actionGet();
        }

        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        String body = "{\"query\" : {\"term\" : { \"_id\" : \"index-pattern:9fbbd1a0-c3c5-11e8-a13f-71b8ea5a4f7b\"}}}";
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest(".kibana/_search/?pretty",body, new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("humanresources"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 1"));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        body =
                "{\"index\":\".kibana\", \"type\":\"doc\", \"ignore_unavailable\": false}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("_msearch/?pretty",body, new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("humanresources"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 1"));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/doc/index-pattern:9fbbd1a0-c3c5-11e8-a13f-71b8ea5a4f7b?pretty", new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("humanresources"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        body = "{\"docs\" : [{\"_index\" : \".kibana\",\"_type\" : \"doc\",\"_id\" : \"index-pattern:9fbbd1a0-c3c5-11e8-a13f-71b8ea5a4f7b\"}]}";
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("_mget/?pretty",body, new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("humanresources"));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        body = "{"+
                "\"type\" : \"index-pattern\","+
                "\"updated_at\" : \"2017-09-29T08:56:59.066Z\","+
                "\"index-pattern\" : {"+
                  "\"title\" : \"xyz\""+
                 "}}";
        Assert.assertEquals(HttpStatus.SC_CREATED, (res = rh.executePutRequest(".kibana/doc/abc?pretty",body, new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("\"result\" : \"created\""));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        body =
                "{ \"index\" : { \"_index\" : \".kibana\", \"_type\" : \"doc\", \"_id\" : \"b1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \".kibana\", \"_type\" : \"doc\", \"_id\" : \"b2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator();

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePutRequest("_bulk?pretty",body, new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));
        Assert.assertTrue(res.getBody().contains("\"errors\" : false"));
        Assert.assertTrue(res.getBody().contains("\"result\" : \"created\""));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_cat/indices", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertEquals(2, res.getBody().split(".kibana").length);
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

    }

    @Test
    public void testDashboardsAlias() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);

        try (TransportClient tc = getInternalTransportClient()) {
            String body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
            Map indexSettings = new HashMap();
            indexSettings.put("number_of_shards", 1);
            indexSettings.put("number_of_replicas", 0);
            tc.admin().indices().create(new CreateIndexRequest(".kibana-6")
                .alias(new Alias(".kibana"))
                .settings(indexSettings))
                .actionGet();

            tc.index(new IndexRequest(".kibana-6").type("doc").id("6.2.2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(body, XContentType.JSON)).actionGet();
        }

        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana-6/doc/6.2.2?pretty", encodeBasicHeader("kibanaro", "kibanaro"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/doc/6.2.2?pretty", encodeBasicHeader("kibanaro", "kibanaro"))).getStatusCode());


    }

    @Test
    public void testDashboardsAlias65() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);

        try (TransportClient tc = getInternalTransportClient()) {
            String body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
            Map indexSettings = new HashMap();
            indexSettings.put("number_of_shards", 1);
            indexSettings.put("number_of_replicas", 0);
            tc.admin().indices().create(new CreateIndexRequest(".kibana_1")
                .alias(new Alias(".kibana"))
                .settings(indexSettings))
                .actionGet();

            tc.index(new IndexRequest(".kibana_1").type("doc").id("6.2.2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(body, XContentType.JSON)).actionGet();
            tc.index(new IndexRequest(".kibana_-900636979_kibanaro").type("doc").id("6.2.2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(body, XContentType.JSON)).actionGet();

        }

        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/doc/6.2.2?pretty", new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("kibanaro", "kibanaro"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains(".kibana_-900636979_kibanaro"));
    }

    @Test
    public void testMultitenancyUserReadOnlyActions() throws Exception {
        setup(Settings.EMPTY);

        /* Create the tenant for the anonymous user to run the tests */
        final String tenant = "test_tenant_ro";

        final TenantExpectation tenantExpectation = new TenantExpectation();
        tenantExpectation.isTenantWritable = "false";
        tenantExpectation.createDocStatusCode = HttpStatus.SC_FORBIDDEN;
        tenantExpectation.updateDocStatusCode = HttpStatus.SC_FORBIDDEN;
        tenantExpectation.updateIndexStatusCode = HttpStatus.SC_FORBIDDEN;
        tenantExpectation.deleteIndexStatuCode = HttpStatus.SC_FORBIDDEN;

        verifyTenantActions(nonSslRestHelper(), tenant, tenantExpectation, encodeBasicHeader("user_a", "user_a"));
    }

    @Test
    public void testMultitenancyUserReadWriteActions() throws Exception {
        setup(Settings.EMPTY);

        /* Create the tenant for the anonymous user to run the tests */
        final String tenant = "opendistro_security_anonymous";

        final TenantExpectation tenantExpectation = new TenantExpectation();
        tenantExpectation.isTenantWritable = "true";
        tenantExpectation.createDocStatusCode = HttpStatus.SC_CREATED;
        tenantExpectation.updateDocStatusCode = HttpStatus.SC_OK;
        tenantExpectation.updateIndexStatusCode = HttpStatus.SC_OK;
        tenantExpectation.deleteIndexStatuCode = HttpStatus.SC_BAD_REQUEST; // tenant index cannot be deleted because its an alias

        verifyTenantActions(nonSslRestHelper(), tenant, tenantExpectation, encodeBasicHeader("admin", "admin"));
    }

    private static void verifyTenantActions(
        final RestHelper rh,
        final String tenant,
        final TenantExpectation tenantExpectation,
        final Header asUser
    ) {
        final BasicHeader inTenant = new BasicHeader("securitytenant", tenant);
        final HttpResponse adminIndexDocToCreateTenant = rh.executePutRequest(
            ".kibana/_doc/5.6.0",
            "{\"buildNum\": 15460, \"defaultIndex\": \"anon\", \"tenant\": \"" + tenant + "\"}",
            encodeBasicHeader("admin", "admin"),
            inTenant
        );
        assertThat(adminIndexDocToCreateTenant.getBody(), adminIndexDocToCreateTenant.getStatusCode(), equalTo(HttpStatus.SC_CREATED));

        final HttpResponse authInfo = rh.executeGetRequest("/_opendistro/_security/authinfo?pretty", inTenant, asUser);
        assertThat(authInfo.getBody(), authInfo.findValueInJson("tenants." + tenant), equalTo(tenantExpectation.isTenantWritable));

        final HttpResponse search = rh.executeGetRequest(".kibana/_search", inTenant, asUser);
        assertThat(search.getBody(), search.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse msearch = rh.executePostRequest(".kibana/_msearch", "{}\n{\"query\":{\"match_all\":{}}}\n", inTenant, asUser);
        assertThat(msearch.getBody(), msearch.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse mget = rh.executePostRequest(".kibana/_mget", "{\"docs\":[{\"_id\":\"5.6.0\"}]}", inTenant, asUser);
        assertThat(mget.getBody(), mget.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse getDoc = rh.executeGetRequest(".kibana/_doc/5.6.0", inTenant, asUser);
        assertThat(getDoc.getBody(), getDoc.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse createDoc = rh.executePostRequest(".kibana/_doc", "{}", inTenant, asUser);
        assertThat(createDoc.getBody(), createDoc.getStatusCode(), equalTo(tenantExpectation.createDocStatusCode));

        final HttpResponse updateDoc = rh.executePutRequest(".kibana/_doc/5.6.0", "{}", inTenant, asUser);
        assertThat(updateDoc.getBody(), updateDoc.getStatusCode(), equalTo(tenantExpectation.updateDocStatusCode));

        final HttpResponse deleteDoc = rh.executeDeleteRequest(".kibana/_doc/5.6.0", inTenant, asUser);
        assertThat(deleteDoc.getBody(), deleteDoc.getStatusCode(), equalTo(tenantExpectation.updateDocStatusCode));

        final HttpResponse getKibana = rh.executeGetRequest(".kibana", inTenant, asUser);
        assertThat(getKibana.getBody(), getKibana.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse closeKibana = rh.executePostRequest(".kibana/_close", "{}", inTenant, asUser);
        assertThat(closeKibana.getBody(), closeKibana.getStatusCode(), equalTo(tenantExpectation.updateIndexStatusCode));

        final HttpResponse deleteKibana = rh.executeDeleteRequest(".kibana", inTenant, asUser);
        assertThat(deleteKibana.getBody(), deleteKibana.getStatusCode(), equalTo(tenantExpectation.deleteIndexStatuCode));
    }

    private static class TenantExpectation {
        private String isTenantWritable;
        private int createDocStatusCode;
        private int updateDocStatusCode;
        private int updateIndexStatusCode;
        private int deleteIndexStatuCode;
    }
}
