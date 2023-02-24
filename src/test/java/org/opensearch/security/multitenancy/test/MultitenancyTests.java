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

package org.opensearch.security.multitenancy.test;

import java.util.HashMap;
import java.util.Map;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
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

            try (Client tc = getClient()) {
                tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();

                tc.index(new IndexRequest("indexa").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexa\"}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("indexb").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexb\"}", XContentType.JSON)).actionGet();


                tc.index(new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("starfleet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("starfleet_academy").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("starfleet_library").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("klingonempire").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

                tc.index(new IndexRequest("spock").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("kirk").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("role01_role02").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();

            }

            HttpResponse resc;
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
            System.out.println(resc.getBody());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_b", "user_b"))).getStatusCode());
            System.out.println(resc.getBody());

            String msearchBody =
                    "{\"index\":\"indexa\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                    "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                    "{\"index\":\"indexb\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                    "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();
            System.out.println("#### msearch a");
            resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_a", "user_a"));
            Assert.assertEquals(200, resc.getStatusCode());
            System.out.println(resc.getBody());
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
            Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

            System.out.println("#### msearch b");
            resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
            Assert.assertEquals(200, resc.getStatusCode());
            System.out.println(resc.getBody());
            Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
            Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

            msearchBody =
                    "{\"index\":\"indexc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                    "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                    "{\"index\":\"indexd\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                    "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

            System.out.println("#### msearch b2");
            resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
            System.out.println(resc.getBody());
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
                            "\"_id\" : \"0\""+
                       " },"+
                       " {"+
                           "\"_index\" : \"indexb\","+
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
                            "\"_id\" : \"0\""+
                       " },"+
                       " {"+
                           "\"_index\" : \"indexy\","+
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
            System.out.println(resc.getBody());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
            System.out.println(resc.getBody());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
            System.out.println(resc.getBody());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("_all/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
            System.out.println(resc.getBody());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("notexists/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
            System.out.println(resc.getBody());

            Assert.assertEquals(HttpStatus.SC_NOT_FOUND, (resc=rh.executeGetRequest("indexanbh,indexabb*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
            System.out.println(resc.getBody());

            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
            System.out.println(resc.getBody());

            Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("worf", "worf"))).getStatusCode());
            System.out.println(resc.getBody());

    }

    @Test
    public void testMt() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        String body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executePutRequest(".kibana/_doc/5.6.0?pretty",body, new BasicHeader("securitytenant", "blafasel"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());

        body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executePutRequest(".kibana/_doc/5.6.0?pretty",body, new BasicHeader("securitytenant", "business_intelligence"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());

        body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
        Assert.assertEquals(HttpStatus.SC_CREATED, (res = rh.executePutRequest(".kibana/_doc/5.6.0?pretty",body, new BasicHeader("securitytenant", "human_resources"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertEquals(".kibana_1592542611_humanresources_1", DefaultObjectMapper.readTree(res.getBody()).get("_index").asText());

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/_doc/5.6.0?pretty",new BasicHeader("securitytenant", "human_resources"), encodeBasicHeader("hr_employee", "hr_employee"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(WildcardMatcher.from("*human_resources*").test(res.getBody()));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana_1592542611_humanresources_1/_alias", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertNotNull(DefaultObjectMapper.readTree(res.getBody()).get(".kibana_1592542611_humanresources_1").get("aliases").get(".kibana_1592542611_humanresources"));

    }


    @Test
    public void testMtMulti() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);

        final String dashboardsIndex = ".kibana_92668751_admin_1";
        try (Client tc = getClient()) {
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

            tc.index(new IndexRequest(dashboardsIndex)
                    .id("index-pattern:9fbbd1a0-c3c5-11e8-a13f-71b8ea5a4f7b")
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(body, XContentType.JSON)).actionGet();
        }

        final RestHelper rh = nonSslRestHelper();

        System.out.println("#### search");
        HttpResponse res;
        String body = "{\"query\" : {\"term\" : { \"_id\" : \"index-pattern:9fbbd1a0-c3c5-11e8-a13f-71b8ea5a4f7b\"}}}";
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest(".kibana/_search/?pretty",body, new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("humanresources"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 1"));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        System.out.println("#### msearch");
        body =
                "{\"index\":\".kibana\", \"ignore_unavailable\": false}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("_msearch/?pretty",body, new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("humanresources"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 1"));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        System.out.println("#### get");
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/_doc/index-pattern:9fbbd1a0-c3c5-11e8-a13f-71b8ea5a4f7b?pretty", new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("humanresources"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        System.out.println("#### mget");
        body = "{\"docs\" : [{\"_index\" : \".kibana\",\"_id\" : \"index-pattern:9fbbd1a0-c3c5-11e8-a13f-71b8ea5a4f7b\"}]}";
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("_mget/?pretty",body, new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("humanresources"));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        System.out.println("#### index");
        body = "{"+
                "\"type\" : \"index-pattern\","+
                "\"updated_at\" : \"2017-09-29T08:56:59.066Z\","+
                "\"index-pattern\" : {"+
                  "\"title\" : \"xyz\""+
                 "}}";
        Assert.assertEquals(HttpStatus.SC_CREATED, (res = rh.executePutRequest(".kibana/_doc/abc?pretty",body, new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("exception"));
        Assert.assertTrue(res.getBody().contains("\"result\" : \"created\""));
        Assert.assertTrue(res.getBody().contains(dashboardsIndex));

        System.out.println("#### bulk");
        body =
                "{ \"index\" : { \"_index\" : \".kibana\", \"_id\" : \"b1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \".kibana\", \"_id\" : \"b2\" } }"+System.lineSeparator()+
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

        try (Client tc = getClient()) {
            String body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
            Map indexSettings = new HashMap();
            indexSettings.put("number_of_shards", 1);
            indexSettings.put("number_of_replicas", 0);
            tc.admin().indices().create(new CreateIndexRequest(".kibana-6")
                .alias(new Alias(".kibana"))
                .settings(indexSettings))
                .actionGet();

            tc.index(new IndexRequest(".kibana-6").id("6.2.2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(body, XContentType.JSON)).actionGet();
        }

        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana-6/_doc/6.2.2?pretty", encodeBasicHeader("kibanaro", "kibanaro"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/_doc/6.2.2?pretty", encodeBasicHeader("kibanaro", "kibanaro"))).getStatusCode());

        System.out.println(res.getBody());

    }

    @Test
    public void testDashboardsAlias65() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);

        try (Client tc = getClient()) {
            String body = "{\"buildNum\": 15460, \"defaultIndex\": \"humanresources\", \"tenant\": \"human_resources\"}";
            Map indexSettings = new HashMap();
            indexSettings.put("number_of_shards", 1);
            indexSettings.put("number_of_replicas", 0);
            tc.admin().indices().create(new CreateIndexRequest(".kibana_1")
                .alias(new Alias(".kibana"))
                .settings(indexSettings))
                .actionGet();

            tc.index(new IndexRequest(".kibana_1").id("6.2.2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(body, XContentType.JSON)).actionGet();
            tc.index(new IndexRequest(".kibana_-900636979_kibanaro").id("6.2.2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(body, XContentType.JSON)).actionGet();

        }

        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest(".kibana/_doc/6.2.2?pretty", new BasicHeader("securitytenant", "__user__"), encodeBasicHeader("kibanaro", "kibanaro"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains(".kibana_-900636979_kibanaro"));
    }


    @Test
    public void testTenantParametersSubstitution() throws Exception {
        final Settings settings = Settings.builder()
                .build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;
        final String url = ".kibana/_doc/5.6.0?pretty";

        final String tenantName = "tenant_parameters_substitution";
        final String createTenantBody = "{\"buildNum\": 15460, \"defaultIndex\": \"plop\", \"tenant\": \"" + tenantName + "\"}";
        final Header asNoAccessUser = encodeBasicHeader("hr_employee", "hr_employee");
        final Header asUser = encodeBasicHeader("user_tenant_parameters_substitution", "user_tenant_parameters_substitution");

        final Header actOnNoAccessTenant = new BasicHeader("securitytenant", "blafasel");
        final Header actOnUserTenant = new BasicHeader("securitytenant", tenantName);

        res = rh.executePutRequest(url, createTenantBody, asUser, actOnNoAccessTenant);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        res = rh.executePutRequest(url, createTenantBody, asNoAccessUser, actOnUserTenant);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        res = rh.executePutRequest(url, createTenantBody, asUser, actOnUserTenant);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_CREATED));

        res = rh.executeGetRequest(url, asUser, actOnUserTenant);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.findValueInJson("_source.tenant"), equalTo(tenantName));


        final String tenantNameAppended = "tenant_parameters_substitution_1";
        final String createTenantAppendedBody = "{\"buildNum\": 15460, \"defaultIndex\": \"plop\", \"tenant\": \"" + tenantNameAppended + "\"}";
        final Header userTenantAppended = new BasicHeader("securitytenant", tenantNameAppended);

        res = rh.executeGetRequest(url, asNoAccessUser, userTenantAppended);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        res = rh.executeGetRequest(url, asUser, userTenantAppended);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_NOT_FOUND));

        res = rh.executePutRequest(url, createTenantAppendedBody, asUser, userTenantAppended);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_CREATED));

        res = rh.executeGetRequest(url, asUser, userTenantAppended);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.findValueInJson("_source.tenant"), equalTo(tenantNameAppended));
    }

    @Test
    public void testMultitenancyAnonymousUser() throws Exception {
        final Settings settings = Settings.builder()
                 .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_anonymous.yml"), settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res;

        /* Create the tenant for the anonymous user to run the tests */
        final String url = ".kibana/_doc/5.6.0?pretty";
        final String anonymousTenant = "anonymous_tenant";
        final String createTenantBody = "{\"buildNum\": 15460, \"defaultIndex\": \"anon\", \"tenant\": \"" + anonymousTenant + "\"}";

        res = rh.executePutRequest(
            url,
            createTenantBody,
            encodeBasicHeader("admin", "admin"),
            new BasicHeader("securitytenant", anonymousTenant)
        );

        /* The anonymous user has access to its tenant */
        res = rh.executeGetRequest(url, new BasicHeader("securitytenant", anonymousTenant));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertEquals(anonymousTenant, res.findValueInJson("_source.tenant"));

        /* No access to other tenants */
        res = rh.executeGetRequest(url, new BasicHeader("securitytenant", "human_resources"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
    }
}
