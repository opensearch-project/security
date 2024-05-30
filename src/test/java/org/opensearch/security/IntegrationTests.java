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

import java.util.TreeSet;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.http.HTTPClientCertAuthenticator;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import io.netty.handler.ssl.OpenSsl;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.DefaultObjectMapper.readTree;

public class IntegrationTests extends SingleClusterTest {

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
        assertThat(
            HttpStatus.SC_OK,
            is(
                (res = rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("nagilum", "nagilum")))
                    .getStatusCode()
            )
        );

        int start = res.getBody().indexOf("_scroll_id") + 15;
        String scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start + 1));
        // search scroll
        assertThat(
            HttpStatus.SC_OK,
            is(
                (res = rh.executePostRequest(
                    "/_search/scroll?pretty=true",
                    "{\"scroll_id\" : \"" + scrollid + "\"}",
                    encodeBasicHeader("nagilum", "nagilum")
                )).getStatusCode()
            )
        );

        // search done

    }

    @Test
    public void testDnParsingCertAuth() throws Exception {
        Settings settings = Settings.builder().put("username_attribute", "cn").put("roles_attribute", "l").build();
        HTTPClientCertAuthenticator auth = new HTTPClientCertAuthenticator(settings, null);
        assertThat(auth.extractCredentials(null, newThreadContext("cn=abc,cn=xxx,l=ert,st=zui,c=qwe")).getUsername(), is("abc"));
        assertThat(auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername(), is("abc"));
        assertThat(auth.extractCredentials(null, newThreadContext("CN=abc,L=ert,st=zui,c=qwe")).getUsername(), is("abc"));
        assertThat(auth.extractCredentials(null, newThreadContext("l=ert,cn=abc,st=zui,c=qwe")).getUsername(), is("abc"));
        Assert.assertNull(auth.extractCredentials(null, newThreadContext("L=ert,CN=abc,c,st=zui,c=qwe")));
        assertThat(auth.extractCredentials(null, newThreadContext("l=ert,st=zui,c=qwe,cn=abc")).getUsername(), is("abc"));
        assertThat(auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe,CN=abc")).getUsername(), is("abc"));
        assertThat(auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe")).getUsername(), is("L=ert,st=zui,c=qwe"));
        Assert.assertArrayEquals(
            new String[] { "ert" },
            auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getBackendRoles().toArray(new String[0])
        );
        Assert.assertArrayEquals(
            new String[] { "bleh", "ert" },
            new TreeSet<>(auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,L=bleh,st=zui,c=qwe")).getBackendRoles()).toArray(
                new String[0]
            )
        );

        settings = Settings.builder().build();
        auth = new HTTPClientCertAuthenticator(settings, null);
        assertThat(
            "cn=abc,l=ert,st=zui,c=qwe",
            is(auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername())
        );
    }

    private ThreadContext newThreadContext(String sslPrincipal) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL, sslPrincipal);
        return threadContext;
    }

    @Test
    public void testDNSpecials() throws Exception {

        final Settings settings = Settings.builder()
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("node-untspec5-keystore.p12")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "1")
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
            .putList(
                ConfigConstants.SECURITY_NODES_DN,
                "EMAILADDRESS=unt@tst.com,CN=node-untspec5.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE"
            )
            .putList(
                ConfigConstants.SECURITY_AUTHCZ_ADMIN_DN,
                "EMAILADDRESS=unt@xxx.com,CN=node-untspec6.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE"
            )
            .put(ConfigConstants.SECURITY_CERT_OID, "1.2.3.4.5.6")
            .build();

        Settings tcSettings = Settings.builder()
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("node-untspec6-keystore.p12")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
            .build();

        setup(tcSettings, new DynamicSecurityConfig(), settings, true);
        RestHelper rh = nonSslRestHelper();

        assertThat(rh.executeGetRequest("").getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));
        assertThat(rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode(), is(HttpStatus.SC_OK));

    }

    @Test
    public void testDNSpecials1() throws Exception {

        final Settings settings = Settings.builder()
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("node-untspec5-keystore.p12")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "1")
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
            .putList("plugins.security.nodes_dn", "EMAILADDRESS=unt@tst.com,CN=node-untspec5.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")
            .putList(
                "plugins.security.authcz.admin_dn",
                "EMAILADDREss=unt@xxx.com,  cn=node-untspec6.example.com, OU=SSL,O=Te\\, st,L=Test, c=DE"
            )
            .put("plugins.security.cert.oid", "1.2.3.4.5.6")
            .build();

        Settings tcSettings = Settings.builder()
            .put(
                "plugins.security.ssl.transport.keystore_filepath",
                FileHelper.getAbsoluteFilePathFromClassPath("node-untspec6-keystore.p12")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
            .build();

        setup(tcSettings, new DynamicSecurityConfig(), settings, true);
        RestHelper rh = nonSslRestHelper();

        assertThat(rh.executeGetRequest("").getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));
        assertThat(rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode(), is(HttpStatus.SC_OK));
    }

    @Test
    public void testEnsureOpenSSLAvailability() {
        Assume.assumeTrue(allowOpenSSL);
        Assert.assertTrue(String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
    }

    @Test
    public void testMultiget() throws Exception {

        setup();

        try (Client tc = getClient()) {
            tc.index(
                new IndexRequest("mindex1").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
            tc.index(
                new IndexRequest("mindex2").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)
            ).actionGet();
        }

        // opendistro_security_multiget -> picard

        String mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"mindex1\","
            + "\"_id\" : \"1\""
            + " },"
            + " {"
            + "\"_index\" : \"mindex2\","
            + " \"_id\" : \"2\""
            + "}"
            + "]"
            + "}";

        RestHelper rh = nonSslRestHelper();
        HttpResponse resc = rh.executePostRequest("_mget?refresh=true", mgetBody, encodeBasicHeader("picard", "picard"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertFalse(resc.getBody().contains("type2"));

    }

    @Test
    public void testRestImpersonation() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS + ".spock", "knuddel", "userwhonotexists")
            .build();

        setup(settings);

        RestHelper rh = nonSslRestHelper();

        // knuddel:
        // hash: _rest_impersonation_only_

        HttpResponse resp;
        resp = rh.executeGetRequest(
            "/_opendistro/_security/authinfo",
            new BasicHeader("opendistro_security_impersonate_as", "knuddel"),
            encodeBasicHeader("worf", "worf")
        );
        assertThat(resp.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resp = rh.executeGetRequest(
            "/_opendistro/_security/authinfo",
            new BasicHeader("opendistro_security_impersonate_as", "knuddel"),
            encodeBasicHeader("spock", "spock")
        );
        assertThat(resp.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(resp.getBody().contains("name=knuddel"));
        Assert.assertFalse(resp.getBody().contains("spock"));

        resp = rh.executeGetRequest(
            "/_opendistro/_security/authinfo",
            new BasicHeader("opendistro_security_impersonate_as", "userwhonotexists"),
            encodeBasicHeader("spock", "spock")
        );
        assertThat(resp.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        resp = rh.executeGetRequest(
            "/_opendistro/_security/authinfo",
            new BasicHeader("opendistro_security_impersonate_as", "invalid"),
            encodeBasicHeader("spock", "spock")
        );
        assertThat(resp.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
    }

    @Test
    public void testSingle() throws Exception {

        setup();

        try (Client tc = getClient()) {
            tc.index(
                new IndexRequest("shakespeare").id("1")
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"content\":1}", XContentType.JSON)
            ).actionGet();

            ConfigUpdateResponse cur = tc.execute(
                ConfigUpdateAction.INSTANCE,
                new ConfigUpdateRequest(new String[] { "config", "roles", "rolesmapping", "internalusers", "actiongroups" })
            ).actionGet();
            assertThat(cur.getNodes().size(), is(clusterInfo.numNodes));
        }

        RestHelper rh = nonSslRestHelper();
        // opendistro_security_shakespeare -> picard

        HttpResponse resc = rh.executeGetRequest("shakespeare/_search", encodeBasicHeader("picard", "picard"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(resc.getBody().contains("\"content\":1"));

        resc = rh.executeHeadRequest("shakespeare", encodeBasicHeader("picard", "picard"));
        assertThat(resc.getStatusCode(), is(HttpStatus.SC_OK));

    }

    @Test
    public void testSpecialUsernames() throws Exception {

        setup();
        RestHelper rh = nonSslRestHelper();

        assertThat(rh.executeGetRequest("", encodeBasicHeader("bug.88", "nagilum")).getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(rh.executeGetRequest("", encodeBasicHeader("a", "b")).getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));
        assertThat(HttpStatus.SC_OK, is(rh.executeGetRequest("", encodeBasicHeader("\"'+-,;_?*@<>!$%&/()=#", "nagilum")).getStatusCode()));
        assertThat(rh.executeGetRequest("", encodeBasicHeader("§ÄÖÜäöüß", "nagilum")).getStatusCode(), is(HttpStatus.SC_OK));

    }

    @Test
    public void testXff() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_xff.yml"), Settings.EMPTY, true);
        RestHelper rh = nonSslRestHelper();
        HttpResponse resc = rh.executeGetRequest(
            "_opendistro/_security/authinfo",
            new BasicHeader("x-forwarded-for", "10.0.0.7"),
            encodeBasicHeader("worf", "worf")
        );
        assertThat(resc.getStatusCode(), is(200));
        Assert.assertTrue(resc.getBody().contains("10.0.0.7"));
    }

    @Test
    public void testRegexExcludes() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY);

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("indexa").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"indexa\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("indexb").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"indexb\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("isallowed").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"isallowed\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("special").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"special\":1}", XContentType.JSON))
                .actionGet();
            tc.index(
                new IndexRequest("alsonotallowed").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"alsonotallowed\":1}", XContentType.JSON)
            ).actionGet();
        }

        RestHelper rh = nonSslRestHelper();
        assertThat(HttpStatus.SC_OK, is(rh.executeGetRequest("index*/_search", encodeBasicHeader("rexclude", "nagilum")).getStatusCode()));
        assertThat(HttpStatus.SC_OK, is(rh.executeGetRequest("indexa/_search", encodeBasicHeader("rexclude", "nagilum")).getStatusCode()));
        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("isallowed/_search", encodeBasicHeader("rexclude", "nagilum")).getStatusCode())
        );
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("special/_search", encodeBasicHeader("rexclude", "nagilum")).getStatusCode())
        );
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("alsonotallowed/_search", encodeBasicHeader("rexclude", "nagilum")).getStatusCode())
        );
    }

    @Test
    public void testMultiRoleSpan() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_multirolespan.yml"), Settings.EMPTY);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("mindex_1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("mindex_2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON))
                .actionGet();
        }

        HttpResponse res = rh.executeGetRequest("/mindex_1,mindex_2/_search", encodeBasicHeader("mindex12", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"content\":1"));
        Assert.assertTrue(res.getBody().contains("\"content\":2"));

    }

    @Test
    public void testMultiRoleSpan2() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_multirolespan.yml"), Settings.EMPTY);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("mindex_1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("mindex_2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("mindex_3").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("mindex_4").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON))
                .actionGet();
        }

        HttpResponse res = rh.executeGetRequest("/mindex_1,mindex_2/_search", encodeBasicHeader("mindex12", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        res = rh.executeGetRequest("/mindex_1,mindex_3/_search", encodeBasicHeader("mindex12", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        res = rh.executeGetRequest("/mindex_1,mindex_4/_search", encodeBasicHeader("mindex12", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

    }

    @Test
    public void testSecurityUnderscore() throws Exception {

        setup();
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res = rh.executePostRequest(
            "abc_xyz_2018_05_24/_doc/1",
            "{\"content\":1}",
            encodeBasicHeader("underscore", "nagilum")
        );

        res = rh.executeGetRequest("abc_xyz_2018_05_24/_doc/1", encodeBasicHeader("underscore", "nagilum"));
        Assert.assertTrue(res.getBody(), res.getBody().contains("\"content\":1"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("abc_xyz_2018_05_24/_refresh", encodeBasicHeader("underscore", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("aaa_bbb_2018_05_24/_refresh", encodeBasicHeader("underscore", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
    }

    @Test
    public void testDeleteByQueryDnfof() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_dnfof.yml"), Settings.EMPTY);

        try (Client tc = getClient()) {
            for (int i = 0; i < 3; i++) {
                tc.index(
                    new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
                ).actionGet();
            }
        }

        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        assertThat(
            HttpStatus.SC_OK,
            is(
                (res = rh.executePostRequest(
                    "/vulcango*/_delete_by_query?refresh=true&wait_for_completion=true&pretty=true",
                    "{\"query\" : {\"match_all\" : {}}}",
                    encodeBasicHeader("nagilum", "nagilum")
                )).getStatusCode()
            )
        );
        Assert.assertTrue(res.getBody().contains("\"deleted\" : 3"));

    }

    @Test
    public void testUpdate() throws Exception {
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, "BOTH").build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            tc.index(
                new IndexRequest("indexc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
            ).actionGet();
        }

        HttpResponse res = rh.executePostRequest(
            "indexc/_update/0?pretty=true&refresh=true",
            "{\"doc\" : {\"content\":2}}",
            encodeBasicHeader("user_c", "user_c")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
    }

    @Test
    public void testDnfof() throws Exception {

        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, "BOTH").build();

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_dnfof.yml"), settings);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();

            tc.index(
                new IndexRequest("indexa").id("0")
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"content\":\"indexa\"}", XContentType.JSON)
            ).actionGet();
            tc.index(
                new IndexRequest("indexb").id("0")
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"content\":\"indexb\"}", XContentType.JSON)
            ).actionGet();

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

        HttpResponse resc;
        assertThat(
            HttpStatus.SC_OK,
            is((resc = rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode())
        );
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));

        assertThat(
            HttpStatus.SC_OK,
            is((resc = rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_b", "user_b"))).getStatusCode())
        );
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));

        String msearchBody = "{\"index\":\"indexa\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"indexb\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"index*\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();
        // msearch
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_a", "user_a"));
        assertThat(resc.getStatusCode(), is(200));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));
        assertThat(resc.getBody().split("\"status\" : 200").length, is(3));
        assertThat(resc.getBody().split("\"status\" : 403").length, is(2));

        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        assertThat(resc.getStatusCode(), is(200));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));
        assertThat(resc.getBody().split("\"status\" : 200").length, is(3));
        assertThat(resc.getBody().split("\"status\" : 403").length, is(2));

        msearchBody = "{\"index\":\"indexc\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"indexd\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();

        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        assertThat(resc.getBody(), resc.getStatusCode(), is(200));
        assertThat(resc.getBody(), resc.findValueInJson("responses[0].error.type"), is("security_exception"));
        assertThat(resc.getBody(), resc.findValueInJson("responses[1].error.type"), is("security_exception"));

        String mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"indexa\","
            + "\"_id\" : \"0\""
            + " },"
            + " {"
            + "\"_index\" : \"indexb\","
            + " \"_id\" : \"0\""
            + "}"
            + "]"
            + "}";

        // mget
        resc = rh.executePostRequest("_mget?pretty", mgetBody, encodeBasicHeader("user_b", "user_b"));
        assertThat(resc.getStatusCode(), is(200));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("\"content\" : \"indexa\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("\"content\" : \"indexb\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"indexx\","
            + "\"_id\" : \"0\""
            + " },"
            + " {"
            + "\"_index\" : \"indexy\","
            + " \"_id\" : \"0\""
            + "}"
            + "]"
            + "}";

        resc = rh.executePostRequest("_mget?pretty", mgetBody, encodeBasicHeader("user_b", "user_b"));
        assertThat(resc.getBody(), resc.getStatusCode(), is(200));
        assertThat(resc.getBody(), resc.findValueInJson("docs[0].error.type"), is("index_not_found_exception"));
        assertThat(resc.getBody(), resc.findValueInJson("docs[1].error.type"), is("index_not_found_exception"));

        assertThat(
            HttpStatus.SC_OK,
            is((resc = rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode())
        );
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));

        assertThat(
            HttpStatus.SC_OK,
            is((resc = rh.executeGetRequest("index*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode())
        );
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));

        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("indexa/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("indexb/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(HttpStatus.SC_OK, is(rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode()));

        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("_all/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("notexists/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_NOT_FOUND,
            is(rh.executeGetRequest("permitnotexistentindex/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("permitnotexistentindex*/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_NOT_FOUND,
            is(rh.executeGetRequest("indexanbh,indexabb*/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode())
        );

        // _all/_mapping/field/*
        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("_all/_mapping/field/*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode())
        );
    }

    @Test
    public void testNoDnfof() throws Exception {

        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, "BOTH").build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);
        final RestHelper rh = nonSslRestHelper();

        try (Client tc = getClient()) {
            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();

            tc.index(
                new IndexRequest("indexa").id("0")
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"content\":\"indexa\"}", XContentType.JSON)
            ).actionGet();
            tc.index(
                new IndexRequest("indexb").id("0")
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"content\":\"indexb\"}", XContentType.JSON)
            ).actionGet();

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

        HttpResponse resc;
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_b", "user_b")).getStatusCode())
        );

        String msearchBody = "{\"index\":\"indexa\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"indexb\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();
        // msearch a
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_a", "user_a"));
        assertThat(resc.getStatusCode(), is(200));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        // msearch b
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        assertThat(resc.getStatusCode(), is(200));

        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        msearchBody = "{\"index\":\"indexc\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"indexd\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();

        // msearch b2
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));

        assertThat(resc.getStatusCode(), is(200));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexc"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexd"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));
        int count = resc.getBody().split("\"status\" : 403").length;
        assertThat(count, is(3));

        String mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"indexa\","
            + "\"_id\" : \"0\""
            + " },"
            + " {"
            + "\"_index\" : \"indexb\","
            + " \"_id\" : \"0\""
            + "}"
            + "]"
            + "}";

        resc = rh.executePostRequest("_mget?pretty", mgetBody, encodeBasicHeader("user_b", "user_b"));
        assertThat(resc.getStatusCode(), is(200));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("\"content\" : \"indexa\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"indexx\","
            + "\"_id\" : \"0\""
            + " },"
            + " {"
            + "\"_index\" : \"indexy\","
            + " \"_id\" : \"0\""
            + "}"
            + "]"
            + "}";

        resc = rh.executePostRequest("_mget?pretty", mgetBody, encodeBasicHeader("user_b", "user_b"));
        assertThat(resc.getStatusCode(), is(200));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        count = resc.getBody().split("root_cause").length;
        assertThat(count, is(3));

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("index*/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("indexa/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("indexb/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("_all/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("notexists/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_NOT_FOUND,
            is(rh.executeGetRequest("indexanbh,indexabb*/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("user_a", "user_a")).getStatusCode())
        );

        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode())
        );

        // _all/_mapping/field/*
        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("_all/_mapping/field/*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode())
        );
        // _mapping/field/*
        assertThat(HttpStatus.SC_OK, is(rh.executeGetRequest("_mapping/field/*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()));
        // */_mapping/field/*
        assertThat(
            HttpStatus.SC_OK,
            is(rh.executeGetRequest("*/_mapping/field/*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode())
        );
    }

    @Test
    public void testSecurityIndexSecurity() throws Exception {
        setup();
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res = rh.executePutRequest(
            ".opendistro_security/_mapping?pretty",
            "{\"properties\": {\"name\":{\"type\":\"text\"}}}",
            encodeBasicHeader("nagilum", "nagilum")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        res = rh.executePutRequest(
            "*dis*rit*/_mapping?pretty",
            "{\"properties\": {\"name\":{\"type\":\"text\"}}}",
            encodeBasicHeader("nagilum", "nagilum")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        res = rh.executePutRequest(
            "*/_mapping?pretty",
            "{\"properties\": {\"name\":{\"type\":\"text\"}}}",
            encodeBasicHeader("nagilum", "nagilum")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        res = rh.executePutRequest(
            "_all/_mapping?pretty",
            "{\"properties\": {\"name\":{\"type\":\"text\"}}}",
            encodeBasicHeader("nagilum", "nagilum")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        res = rh.executePostRequest(".opendistro_security/_close", "", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        res = rh.executeDeleteRequest(".opendistro_security", encodeBasicHeader("nagilum", "nagilum"));
        res = rh.executeDeleteRequest("_all", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        res = rh.executePutRequest(
            ".opendistro_security/_settings",
            "{\"index\" : {\"number_of_replicas\" : 2}}",
            encodeBasicHeader("nagilum", "nagilum")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        res = rh.executePutRequest(
            ".opendistro_secur*/_settings",
            "{\"index\" : {\"number_of_replicas\" : 2}}",
            encodeBasicHeader("nagilum", "nagilum")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        res = rh.executePostRequest(".opendistro_security/_freeze", "", encodeBasicHeader("nagilum", "nagilum"));
        assertThat(res.getStatusCode(), is(400));

        String bulkBody = "{ \"index\" : { \"_index\" : \".opendistro_security\", \"_id\" : \"1\" } }\n"
            + "{ \"field1\" : \"value1\" }\n"
            + "{ \"index\" : { \"_index\" : \".opendistro_security\", \"_id\" : \"2\" } }\n"
            + "{ \"field2\" : \"value2\" }\n"
            + "{ \"index\" : { \"_index\" : \"myindex\", \"_id\" : \"2\" } }\n"
            + "{ \"field2\" : \"value2\" }\n"
            + "{ \"delete\" : { \"_index\" : \".opendistro_security\", \"_id\" : \"config\" } }\n";
        res = rh.executePostRequest("_bulk?refresh=true&pretty", bulkBody, encodeBasicHeader("nagilum", "nagilum"));
        JsonNode jsonNode = readTree(res.getBody());

        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(jsonNode.get("items").get(0).get("index").get("status").intValue(), is(403));
        assertThat(jsonNode.get("items").get(1).get("index").get("status").intValue(), is(403));
        assertThat(jsonNode.get("items").get(2).get("index").get("status").intValue(), is(201));
        assertThat(jsonNode.get("items").get(3).get("delete").get("status").intValue(), is(403));
    }

    @Test
    public void testMonitorHealth() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY);

        RestHelper rh = nonSslRestHelper();
        assertThat(rh.executeGetRequest("_cat/health", encodeBasicHeader("picard", "picard")).getStatusCode(), is(HttpStatus.SC_OK));
    }
}
