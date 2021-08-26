/*
 *   Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

package org.opensearch.security;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;


public class ResolveAPITests extends SingleClusterTest {
    
    protected final Logger log = LogManager.getLogger(this.getClass());

    @Test
    public void testResolveDnfofFalse() throws Exception {

        Settings settings = Settings.builder().build();

        setup(settings);
        setupIndices();

        final RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_resolve/index/*?pretty", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        log.debug(res.getBody());
        assertNotContains(res, "*xception*");
        assertNotContains(res, "*erial*");
        assertNotContains(res, "*mpty*");
        assertContains(res, "*vulcangov*");
        assertContains(res, "*starfleet*");
        assertContains(res, "*klingonempire*");
        assertContains(res, "*xyz*");
        assertContains(res, "*role01_role02*");

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_resolve/index/starfleet*?pretty", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        log.debug(res.getBody());
        assertNotContains(res, "*xception*");
        assertNotContains(res, "*erial*");
        assertNotContains(res, "*mpty*");
        assertNotContains(res, "*vulcangov*");
        assertNotContains(res, "*klingonempire*");
        assertNotContains(res, "*xyz*");
        assertNotContains(res, "*role01_role02*");
        assertContains(res, "*starfleet*");
        assertContains(res, "*starfleet_academy*");
        assertContains(res, "*starfleet_library*");

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("_resolve/index/*?pretty",  encodeBasicHeader("worf", "worf"))).getStatusCode());
        log.debug(res.getBody());

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_resolve/index/starfleet*?pretty",  encodeBasicHeader("worf", "worf"))).getStatusCode());
        log.debug(res.getBody());
        assertContains(res, "*starfleet*");
        assertContains(res, "*starfleet_academy*");
        assertContains(res, "*starfleet_library*");
    }

    @Test
    public void testResolveDnfofTrue() throws Exception {
        final Settings settings = Settings.builder().build();

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_dnfof.yml"), settings);
        setupIndices();

        final RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_resolve/index/*?pretty", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        log.debug(res.getBody());
        assertNotContains(res, "*xception*");
        assertNotContains(res, "*erial*");
        assertNotContains(res, "*mpty*");
        assertContains(res, "*vulcangov*");
        assertContains(res, "*starfleet*");
        assertContains(res, "*klingonempire*");
        assertContains(res, "*xyz*");
        assertContains(res, "*role01_role02*");

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_resolve/index/starfleet*?pretty", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        log.debug(res.getBody());
        assertNotContains(res, "*xception*");
        assertNotContains(res, "*erial*");
        assertNotContains(res, "*mpty*");
        assertNotContains(res, "*vulcangov*");
        assertNotContains(res, "*klingonempire*");
        assertNotContains(res, "*xyz*");
        assertNotContains(res, "*role01_role02*");
        assertContains(res, "*starfleet*");
        assertContains(res, "*starfleet_academy*");
        assertContains(res, "*starfleet_library*");

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_resolve/index/*?pretty",  encodeBasicHeader("worf", "worf"))).getStatusCode());
        log.debug(res.getBody());
        assertNotContains(res, "*xception*");
        assertNotContains(res, "*erial*");
        assertNotContains(res, "*mpty*");
        assertNotContains(res, "*vulcangov*");
        assertNotContains(res, "*kirk*");
        assertContains(res, "*starfleet*");
        assertContains(res, "*public*");
        assertContains(res, "*xyz*");

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_resolve/index/starfleet*?pretty",  encodeBasicHeader("worf", "worf"))).getStatusCode());
        log.debug(res.getBody());
        assertNotContains(res, "*xception*");
        assertNotContains(res, "*erial*");
        assertNotContains(res, "*mpty*");
        assertNotContains(res, "*vulcangov*");
        assertNotContains(res, "*kirk*");
        assertNotContains(res, "*public*");
        assertNotContains(res, "*xyz*");
        assertContains(res, "*starfleet*");
        assertContains(res, "*starfleet_academy*");
        assertContains(res, "*starfleet_library*");

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("_resolve/index/vulcangov*?pretty",  encodeBasicHeader("worf", "worf"))).getStatusCode());
        log.debug(res.getBody());
    }

    private void setupIndices() {
        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.index(new IndexRequest("spock").type("type01").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("kirk").type("type01").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("role01_role02").type("type01").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.index(new IndexRequest("xyz").type("doc").setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(IndicesAliasesRequest.AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(IndicesAliasesRequest.AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(IndicesAliasesRequest.AliasActions.add().indices("public").alias("unrestricted"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(IndicesAliasesRequest.AliasActions.add().indices("xyz").alias("alias1"))).actionGet();
        }
    }
}
