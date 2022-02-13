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

package org.opensearch.security.auditlog.integration;

import org.opensearch.security.auditlog.AuditTestUtils;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.compliance.ComplianceConfig;
import com.google.common.collect.ImmutableMap;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.NoHttpResponseException;
import org.apache.http.message.BasicHeader;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import java.util.Collections;

public class BasicAuditlogTest extends AbstractAuditlogiUnitTest {

    @Test
    public void testAuditLogEnable() throws Exception {
        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .build();

        setup(additionalSettings);
        setupStarfleetIndex();

        AuditConfig auditConfig = new AuditConfig(true, AuditConfig.Filter.from(ImmutableMap.of("disabled_rest_categories", Collections.emptySet(), "disabled_transport_categories", Collections.emptySet())) , ComplianceConfig.DEFAULT);
        updateAuditConfig(AuditTestUtils.createAuditPayload(auditConfig));

        // test enable
        TestAuditlogImpl.clear();
        rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin"));
        Assert.assertTrue(TestAuditlogImpl.messages.size() > 0);

        // disable
        auditConfig = new AuditConfig(false, AuditConfig.Filter.from(ImmutableMap.of("disabled_rest_categories", Collections.emptySet(), "disabled_transport_categories", Collections.emptySet())) , ComplianceConfig.DEFAULT);
        updateAuditConfig(AuditTestUtils.createAuditPayload(auditConfig));

        // assert no auditing
        TestAuditlogImpl.clear();
        rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(0, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testSimpleAuthenticated() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated")
                .build();

        setup(additionalSettings);
        setupStarfleetIndex();
        TestAuditlogImpl.clear();

        System.out.println("#### testSimpleAuthenticated");
        HttpResponse response = rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Thread.sleep(1500);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("GRANTED_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/read/search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("REST"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().toLowerCase().contains("authorization"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testSSLPlainText() throws Exception {
    //if this fails permanently look in the logs for an abstract method error or method not found error.
    //needs proper ssl plugin version

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.ssl.http.enabled",true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore.jks"))
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);
        TestAuditlogImpl.clear();

        try {
            nonSslRestHelper().executeGetRequest("_search", encodeBasicHeader("admin", "admin"));
            Assert.fail();
        } catch (NoHttpResponseException e) {
            //expected
        }

        Thread.sleep(1500);
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertFalse(TestAuditlogImpl.messages.isEmpty());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("SSL_EXCEPTION"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("exception_stacktrace"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("not an SSL/TLS record"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testSimpleTransportAuthenticated() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);
        setupStarfleetIndex();
        TestAuditlogImpl.clear();

        System.out.println("#### testSimpleAuthenticated");
        try (TransportClient tc = getUserTransportClient(clusterInfo, "spock-keystore.jks", Settings.EMPTY)) {
            StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
            try {
                Header header = encodeBasicHeader("admin", "admin");
                tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                SearchResponse res = tc.search(new SearchRequest()).actionGet();
                System.out.println(res);
            } finally {
                ctx.close();
            }
        }

        Thread.sleep(1500);
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue("Was "+TestAuditlogImpl.messages.size(), TestAuditlogImpl.messages.size() >= 2);
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("GRANTED_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/read/search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("TRANSPORT"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_request_effective_user\" : \"admin\""));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("REST"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().toLowerCase().contains("authorization"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testTaskId() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);
        setupStarfleetIndex();
        TestAuditlogImpl.clear();

        try (TransportClient tc = getUserTransportClient(clusterInfo, "spock-keystore.jks", Settings.EMPTY)) {
            StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
            try {
                Header header = encodeBasicHeader("admin", "admin");
                tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                SearchResponse res = tc.search(new SearchRequest()).actionGet();
                System.out.println(res);
            } finally {
                ctx.close();
            }
        }

        Thread.sleep(1500);
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(String.valueOf(TestAuditlogImpl.messages.size()), TestAuditlogImpl.messages.size() >= 2);
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("GRANTED_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/read/search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("TRANSPORT"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_request_effective_user\" : \"admin\""));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("REST"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().toLowerCase().contains("authorization"));
        Assert.assertEquals(TestAuditlogImpl.messages.get(1).getAsMap().get(AuditMessage.TASK_ID),
        TestAuditlogImpl.messages.get(1).getAsMap().get(AuditMessage.TASK_ID));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testDefaultsRest() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);
        setupStarfleetIndex();
        TestAuditlogImpl.clear();

        HttpResponse response = rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        Thread.sleep(1500);
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertEquals(2, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("GRANTED_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/read/search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("TRANSPORT"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_request_effective_user\" : \"admin\""));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("REST"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().toLowerCase().contains("authorization"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testGrantedPrivilegesRest() throws Exception {
        final Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "AUTHENTICATED")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .build();

        setup(additionalSettings);
        setupStarfleetIndex();

        testPrivilegeRest(HttpStatus.SC_OK, "/_opendistro/_security/api/roles", AuditCategory.GRANTED_PRIVILEGES);
    }

    @Test
    public void testMissingPrivilegesRest() throws Exception {
        final Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "AUTHENTICATED")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .build();
        setup(additionalSettings);
        setupStarfleetIndex();

        testPrivilegeRest(HttpStatus.SC_FORBIDDEN, "/_opendistro/_security/api/roles", AuditCategory.MISSING_PRIVILEGES);
    }

    private void testPrivilegeRest(final int expectedStatus, final String endpoint, final AuditCategory category) throws Exception {
        TestAuditlogImpl.clear();
        final HttpResponse response = rh.executeGetRequest(endpoint, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(expectedStatus, response.getStatusCode());
        final String auditlog = TestAuditlogImpl.sb.toString();
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(auditlog.contains("\"audit_category\" : \"" + category +"\""));
        Assert.assertTrue(auditlog.contains("\"audit_rest_request_path\" : \"" + endpoint + "\""));
        Assert.assertTrue(auditlog.contains("\"audit_request_effective_user\" : \"admin\""));
    }

    @Test
    public void testAuthenticated() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);
        setupStarfleetIndex();
        TestAuditlogImpl.clear();

        testMsearch();
        TestAuditlogImpl.clear();

        testBulkAuth();
        TestAuditlogImpl.clear();

        testBulkNonAuth();
        TestAuditlogImpl.clear();

        testUpdateSettings();
        TestAuditlogImpl.clear();
    }

    @Test
    public void testNonAuthenticated() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .build();

        setup(additionalSettings);
        setupStarfleetIndex();
        TestAuditlogImpl.clear();

        testJustAuthenticated();
        TestAuditlogImpl.clear();
        testBadHeader();
        TestAuditlogImpl.clear();
        testMissingPriv();
        TestAuditlogImpl.clear();
        testSecurityIndexAttempt();
        TestAuditlogImpl.clear();
        testUnauthenticated();
        TestAuditlogImpl.clear();
        testUnknownAuthorization();
        TestAuditlogImpl.clear();
        testWrongUser();
        TestAuditlogImpl.clear();

    }

    public void testWrongUser() throws Exception {

        HttpResponse response = rh.executeGetRequest("", encodeBasicHeader("wronguser", "admin"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(500);
        Assert.assertTrue(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains("FAILED_LOGIN"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains("wronguser"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains(AuditMessage.UTC_TIMESTAMP));
        Assert.assertFalse(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }


    public void testUnknownAuthorization() throws Exception {

        HttpResponse response = rh.executeGetRequest("", encodeBasicHeader("unknown", "unknown"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("FAILED_LOGIN"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString(),TestAuditlogImpl.sb.toString().contains("Basic dW5rbm93bjp1bmtub3du"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(AuditMessage.UTC_TIMESTAMP));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }


    public void testUnauthenticated() throws Exception {

        System.out.println("#### testUnauthenticated");
        HttpResponse response = rh.executeGetRequest("_search");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(1500);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("FAILED_LOGIN"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("<NONE>"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("/_search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(AuditMessage.UTC_TIMESTAMP));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));

    }

    public void testJustAuthenticated() throws Exception {
        HttpResponse response = rh.executeGetRequest("", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertEquals(0, TestAuditlogImpl.messages.size());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }


    public void testSecurityIndexAttempt() throws Exception {

        HttpResponse response = rh.executePutRequest(".opendistro_security/config/0", "{}", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("OPENDISTRO_SECURITY_INDEX_ATTEMPT"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("admin"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(AuditMessage.UTC_TIMESTAMP));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(2, TestAuditlogImpl.messages.size());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }


    public void testBadHeader() throws Exception {

        HttpResponse response = rh.executeGetRequest("", new BasicHeader("_opendistro_security_bad", "bad"), encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertFalse(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("BAD_HEADERS"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("_opendistro_security_bad"));
        Assert.assertEquals(TestAuditlogImpl.sb.toString(), 1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }


    public void testMissingPriv() throws Exception {

        HttpResponse response = rh.executeGetRequest("sf/_search", encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/read/search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("worf"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"sf\""));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(AuditMessage.UTC_TIMESTAMP));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

	public void testMsearch() throws Exception {

        String msearch =
                "{\"index\":\"sf\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":0,\"query\":{\"match_all\":{}}}"+System.lineSeparator()+
                "{\"index\":\"sf\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":0,\"query\":{\"match_all\":{}}}"+System.lineSeparator();

        System.out.println("##### msaerch");
        HttpResponse response = rh.executePostRequest("_msearch?pretty", msearch, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(response.getStatusReason(), HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("indices:data/read/msearch"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("indices:data/read/search"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("match_all"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("audit_trace_task_id"));
        Assert.assertEquals(TestAuditlogImpl.sb.toString(), 4, TestAuditlogImpl.messages.size());
        Assert.assertFalse(TestAuditlogImpl.sb.toString().toLowerCase().contains("authorization"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
	}


    public void testBulkAuth() throws Exception {

        System.out.println("#### testBulkAuth");
        String bulkBody =
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"worf\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+

                "{ \"update\" : {\"_id\" : \"1\", \"_type\" : \"type1\", \"_index\" : \"test\"} }"+System.lineSeparator()+
                "{ \"doc\" : {\"field\" : \"valuex\"} }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"create\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value3x\" }"+System.lineSeparator();


        HttpResponse response = rh.executePostRequest("_bulk", bulkBody, encodeBasicHeader("admin", "admin"));
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"errors\":false"));
        Assert.assertTrue(response.getBody().contains("\"status\":201"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:admin/auto_create"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/write/bulk"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("IndexRequest"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("audit_trace_task_parent_id"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("audit_trace_task_id"));
        //may vary because we log shardrequests which are not predictable here
        Assert.assertTrue(TestAuditlogImpl.messages.size() >= 17);
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    public void testBulkNonAuth() throws Exception {

        String bulkBody =
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"worf\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+

                "{ \"update\" : {\"_id\" : \"1\", \"_type\" : \"type1\", \"_index\" : \"test\"} }"+System.lineSeparator()+
                "{ \"doc\" : {\"field\" : \"valuex\"} }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"create\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value3x\" }"+System.lineSeparator();

        HttpResponse response = rh.executePostRequest("_bulk", bulkBody, encodeBasicHeader("worf", "worf"));
        System.out.println(response.getBody());

        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"errors\":true"));
        Assert.assertTrue(response.getBody().contains("\"status\":200"));
        Assert.assertTrue(response.getBody().contains("\"status\":403"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/write/bulk[s]"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("IndexRequest"));
        //may vary because we log shardrequests which are not predictable here
        Assert.assertTrue(TestAuditlogImpl.messages.size() >= 7);
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    public void testUpdateSettings() throws Exception {

        String json =
        "{"+
            "\"persistent\" : {"+
                "\"discovery.zen.minimum_master_nodes\" : 1"+
            "},"+
            "\"transient\" : {"+
                "\"discovery.zen.minimum_master_nodes\" : 1"+
             "}"+
        "}";

        HttpResponse response = rh.executePutRequest("_cluster/settings", json, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("cluster:admin/settings/update"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("discovery.zen.minimum_master_nodes"));
        //may vary because we log may hit master directly or not
        Assert.assertTrue(TestAuditlogImpl.messages.size() > 1);
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testIndexPattern() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", "internal_opensearch")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .put("plugins.security.audit.threadpool.size", 10) //must be greater 0
                .put("plugins.security.audit.config.index", "'auditlog-'YYYY.MM.dd.ss")
                .build();

        setup(additionalSettings);
        setupStarfleetIndex();

        final boolean sendAdminCertificate = rh.sendAdminCertificate;
        final String keystore = rh.keystore;
        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";
        HttpResponse res = rh.executeGetRequest("_cat/indices", new Header[0]);
        rh.sendAdminCertificate = sendAdminCertificate;
        rh.keystore = keystore;

        Assert.assertTrue(res.getBody().contains("auditlog-20"));
    }

    @Test
    public void testAliases() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);

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

        TestAuditlogImpl.clear();

        HttpResponse response = rh.executeGetRequest("sf/_search?pretty", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("starfleet_academy"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("starfleet_library"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("starfleet"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("sf"));
        Assert.assertEquals(2, TestAuditlogImpl.messages.size());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testScroll() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);

        try (TransportClient tc = getInternalTransportClient()) {
            for(int i=0; i<3; i++)
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
        }

        TestAuditlogImpl.clear();

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("admin", "admin"))).getStatusCode());
        int start = res.getBody().indexOf("_scroll_id") + 15;
        String scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start+1));
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executePostRequest("/_search/scroll?pretty=true", "{\"scroll_id\" : \""+scrollid+"\"}", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertEquals(4, TestAuditlogImpl.messages.size());

        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("admin", "admin"))).getStatusCode());
        start = res.getBody().indexOf("_scroll_id") + 15;
        scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start+1));
        TestAuditlogImpl.clear();
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res=rh.executePostRequest("/_search/scroll?pretty=true", "{\"scroll_id\" : \""+scrollid+"\"}", encodeBasicHeader("admin2", "admin"))).getStatusCode());
        Thread.sleep(1000);
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("InternalScrollSearchRequest"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.messages.size() > 2);
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testAliasResolution() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);


        try (TransportClient tc = getInternalTransportClient()) {
            for(int i=0; i<3; i++)
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().alias("thealias").index("vulcangov"))).actionGet();
        }

        TestAuditlogImpl.clear();
        HttpResponse response = rh.executeGetRequest("thealias/_search?pretty", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("thealias"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("audit_trace_resolved_indices"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("vulcangov"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
        TestAuditlogImpl.clear();
    }

    @Test
    public void testAliasBadHeaders() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);

        TestAuditlogImpl.clear();
        HttpResponse response = rh.executeGetRequest("_search?pretty", new BasicHeader("_opendistro_security_user", "xxx"), encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("YWRtaW46YWRtaW4"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("BAD_HEADERS"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("xxx"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
        TestAuditlogImpl.clear();
    }

    @Test
    public void testIndexCloseDelete() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();

        setup(additionalSettings);

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest("index1")).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("index2")).actionGet();
        }

        TestAuditlogImpl.clear();

        HttpResponse response = rh.executeDeleteRequest("index1?pretty", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executePostRequest("index2/_close?pretty", "", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:admin/close"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:admin/delete"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.messages.size() >= 2);
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testDeleteByQuery() throws Exception {

        final Settings settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .build();
        setup(settings);

        try (TransportClient tc = getInternalTransportClient()) {
            for(int i=0; i<3; i++)
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
        }

        TestAuditlogImpl.clear();

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executePostRequest("/vulcango*/_delete_by_query?refresh=true&wait_for_completion=true&pretty=true", "{\"query\" : {\"match_all\" : {}}}", encodeBasicHeader("admin", "admin"))).getStatusCode());
        assertContains(res, "*\"deleted\" : 3,*");
        String auditlogContents = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogContents.contains("indices:data/write/delete/byquery"));
        Assert.assertTrue(auditlogContents.contains("indices:data/write/bulk"));
        Assert.assertTrue(auditlogContents.contains("indices:data/read/search"));
    }

    @Test
    public void testIndexRequests() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "AUTHENTICATED,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true)
                .build();
        setup(settings);

        // test create index
        TestAuditlogImpl.clear();
        rh.executePutRequest("/twitter", "{\"settings\":{\"index\":{\"number_of_shards\":3,\"number_of_replicas\":2}}}", encodeBasicHeader("admin", "admin"));
        String auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("\"audit_category\" : \"INDEX_EVENT\""));
        Assert.assertTrue(auditlogs.contains("\"audit_transport_request_type\" : \"CreateIndexRequest\","));
        Assert.assertTrue(auditlogs.contains("\"audit_request_body\" : \"{\\\"index\\\":{\\\"number_of_shards\\\":\\\"3\\\",\\\"number_of_replicas\\\":\\\"2\\\"}}\""));

        // test update index
        TestAuditlogImpl.clear();
        rh.executePutRequest("/twitter/_settings", "{\"index\":{\"number_of_replicas\":1}}", encodeBasicHeader("admin", "admin"));
        auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("\"audit_category\" : \"INDEX_EVENT\""));
        Assert.assertTrue(auditlogs.contains("\"audit_transport_request_type\" : \"UpdateSettingsRequest\","));
        Assert.assertTrue(auditlogs.contains("\"audit_request_body\" : \"{\\\"index\\\":{\\\"number_of_replicas\\\":\\\"1\\\"}}\""));

        // test put mapping
        TestAuditlogImpl.clear();
        rh.executePutRequest("/twitter/_mapping", "{\"properties\":{\"message\":{\"type\":\"keyword\"}}}", encodeBasicHeader("admin", "admin"));
        auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("\"audit_category\" : \"INDEX_EVENT\""));
        Assert.assertTrue(auditlogs.contains("\"audit_transport_request_type\" : \"PutMappingRequest\","));
        Assert.assertTrue(auditlogs.contains("\"{\\\"properties\\\":{\\\"message\\\":{\\\"type\\\":\\\"keyword\\\"}}}\""));

        // test delete index
        TestAuditlogImpl.clear();
        rh.executeDeleteRequest("/twitter", encodeBasicHeader("admin", "admin"));
        auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("\"audit_category\" : \"INDEX_EVENT\""));
        Assert.assertTrue(auditlogs.contains("\"audit_transport_request_type\" : \"DeleteIndexRequest\","));
    }

    @Test
    public void testRestMethod() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .build();
        setup(settings);
        final Header adminHeader = encodeBasicHeader("admin", "admin");

        // test GET
        TestAuditlogImpl.clear();
        rh.executeGetRequest("test", adminHeader);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_rest_request_method\" : \"GET\""));

        // test PUT
        TestAuditlogImpl.clear();
        rh.executePutRequest("test/_doc/0", "{}", adminHeader);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_rest_request_method\" : \"PUT\""));

        // test DELETE
        TestAuditlogImpl.clear();
        rh.executeDeleteRequest("test", adminHeader);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_rest_request_method\" : \"DELETE\""));

        // test POST
        TestAuditlogImpl.clear();
        rh.executePostRequest("test/_doc", "{}", adminHeader);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_rest_request_method\" : \"POST\""));

        // test PATCH
        TestAuditlogImpl.clear();
        rh.executePatchRequest("/_opendistro/_security/api/audit", "[]");
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_rest_request_method\" : \"PATCH\""));

        // test MISSING_PRIVILEGES
        // admin does not have REST role here
        TestAuditlogImpl.clear();
        rh.executePatchRequest("/_opendistro/_security/api/audit", "[]", adminHeader);
        Assert.assertEquals(2, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_rest_request_method\" : \"PATCH\""));

        // test AUTHENTICATED
        TestAuditlogImpl.clear();
        rh.executeGetRequest("test", adminHeader);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_rest_request_method\" : \"GET\""));

        // test FAILED_LOGIN
        TestAuditlogImpl.clear();
        rh.executeGetRequest("test", encodeBasicHeader("random", "random"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("FAILED_LOGIN"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_rest_request_method\" : \"GET\""));

        // test BAD_HEADERS
        TestAuditlogImpl.clear();
        rh.executeGetRequest("test", new BasicHeader("_opendistro_security_user", "xxx"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("BAD_HEADERS"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\"audit_rest_request_method\" : \"GET\""));
    }

    @Test
    public void testSensitiveMethodRedaction() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "AUTHENTICATED")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .build();
        setup(settings);
        rh.sendAdminCertificate = true;
        final String expectedRequestBody = "\"audit_request_body\" : \"__SENSITIVE__\"";

        // test PUT accounts API
        TestAuditlogImpl.clear();
        rh.executePutRequest("/_opendistro/_security/api/account", "{\"password\":\"new-pass\", \"current_password\":\"curr-passs\"}");
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(expectedRequestBody));

        // test PUT internal users API
        TestAuditlogImpl.clear();
        rh.executePutRequest("/_opendistro/_security/api/internalusers/test1", "{\"password\":\"new-pass\", \"backend_roles\":[], \"attributes\": {}}");
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(expectedRequestBody));

        // test PATCH internal users API
        TestAuditlogImpl.clear();
        rh.executePatchRequest("/_opendistro/_security/api/internalusers/test1", "[{\"op\":\"add\", \"path\":\"/password\", \"value\": \"test-pass\"}]");
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(expectedRequestBody));

        // test PUT users API
        TestAuditlogImpl.clear();
        rh.executePutRequest("/_opendistro/_security/api/user/test2", "{\"password\":\"new-pass\", \"backend_roles\":[], \"attributes\": {}}");
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(expectedRequestBody));
    }
}
