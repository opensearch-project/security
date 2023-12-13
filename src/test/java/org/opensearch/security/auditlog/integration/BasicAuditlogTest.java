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

package org.opensearch.security.auditlog.integration;

import java.util.Collections;
import java.util.List;

import com.google.common.collect.ImmutableMap;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
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
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.AuditTestUtils;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.config.AuditConfig.Filter.FilterEntries;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PATCH;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;

public class BasicAuditlogTest extends AbstractAuditlogiUnitTest {

    @Test
    public void testAuditLogEnable() throws Exception {
        Settings additionalSettings = Settings.builder().put("plugins.security.audit.type", TestAuditlogImpl.class.getName()).build();

        setup(additionalSettings);
        setupStarfleetIndex();

        AuditConfig auditConfig = new AuditConfig(
            true,
            AuditConfig.Filter.from(
                ImmutableMap.of("disabled_rest_categories", Collections.emptySet(), "disabled_transport_categories", Collections.emptySet())
            ),
            ComplianceConfig.DEFAULT
        );
        updateAuditConfig(AuditTestUtils.createAuditPayload(auditConfig));

        // test enable
        TestAuditlogImpl.clear();
        rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin"));
        Assert.assertTrue(TestAuditlogImpl.messages.size() > 0);

        // disable
        auditConfig = new AuditConfig(
            false,
            AuditConfig.Filter.from(
                ImmutableMap.of("disabled_rest_categories", Collections.emptySet(), "disabled_transport_categories", Collections.emptySet())
            ),
            ComplianceConfig.DEFAULT
        );
        updateAuditConfig(AuditTestUtils.createAuditPayload(auditConfig));

        // assert no auditing
        TestAuditlogImpl.clear();
        rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(0, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testSimpleAuthenticatedSetting() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(FilterEntries.DISABLE_TRANSPORT_CATEGORIES.getKeyWithNamespace(), "NONE")
            .build();
        verifyAuthenticated(settings);
    }

    @Test
    public void testSimpleAuthenticatedLegacySetting() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .build();
        verifyAuthenticated(settings);
    }

    private void verifyAuthenticated(final Settings settings) throws Exception {
        setup(settings);

        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            final HttpResponse response = rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin"));
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }, /* expectedCount*/ 1);

        assertThat(messages.size(), equalTo(1));

        assertThat(messages.get(0).getCategory(), equalTo(AuditCategory.GRANTED_PRIVILEGES));
        assertThat(messages.get(0).getOrigin(), equalTo(Origin.REST));
        assertThat(messages.get(0).getPrivilege(), equalTo("indices:data/read/search"));
    }

    @Test
    public void testSSLPlainText() throws Exception {
        // if this fails permanently look in the logs for an abstract method error or method not found error.
        // needs proper ssl plugin version

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore.jks"))
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
            .build();

        setup(additionalSettings);
        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            final RuntimeException ex = Assert.assertThrows(
                RuntimeException.class,
                () -> nonSslRestHelper().executeGetRequest("_search", encodeBasicHeader("admin", "admin"))
            );
            Assert.assertEquals("org.apache.http.NoHttpResponseException", ex.getCause().getClass().getName());
        }, 1);

        // All of the messages should be the same as the http client is attempting multiple times.
        messages.stream().forEach((message) -> {
            Assert.assertEquals(AuditCategory.SSL_EXCEPTION, message.getCategory());
            Assert.assertTrue(message.getExceptionStackTrace().contains("not an SSL/TLS record"));
        });
        validateMsgs(messages);
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

        HttpResponse response = rh.executeGetRequest("_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        Thread.sleep(1500);
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(String.valueOf(TestAuditlogImpl.messages.size()), TestAuditlogImpl.messages.size() >= 2);
        Assert.assertTrue(auditLogImpl.contains("GRANTED_PRIVILEGES"));
        Assert.assertTrue(auditLogImpl.contains("AUTHENTICATED"));
        Assert.assertTrue(auditLogImpl.contains("indices:data/read/search"));
        Assert.assertTrue(auditLogImpl.contains("TRANSPORT"));
        Assert.assertTrue(auditLogImpl.contains("\"audit_request_effective_user\" : \"admin\""));
        Assert.assertTrue(auditLogImpl.contains("REST"));
        Assert.assertFalse(auditLogImpl.toLowerCase().contains("authorization"));
        Assert.assertEquals(
            TestAuditlogImpl.messages.get(1).getAsMap().get(AuditMessage.TASK_ID),
            TestAuditlogImpl.messages.get(1).getAsMap().get(AuditMessage.TASK_ID)
        );
        validateMsgs(TestAuditlogImpl.messages);
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
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertEquals(2, TestAuditlogImpl.messages.size());
        Assert.assertTrue(auditLogImpl.contains("GRANTED_PRIVILEGES"));
        Assert.assertTrue(auditLogImpl.contains("AUTHENTICATED"));
        Assert.assertTrue(auditLogImpl.contains("indices:data/read/search"));
        Assert.assertTrue(auditLogImpl.contains("TRANSPORT"));
        Assert.assertTrue(auditLogImpl.contains("\"audit_request_effective_user\" : \"admin\""));
        Assert.assertTrue(auditLogImpl.contains("REST"));
        Assert.assertFalse(auditLogImpl.toLowerCase().contains("authorization"));
        validateMsgs(TestAuditlogImpl.messages);
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
        Assert.assertTrue(auditlog.contains("\"audit_category\" : \"" + category + "\""));
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

        Settings additionalSettings = Settings.builder().put("plugins.security.audit.type", TestAuditlogImpl.class.getName()).build();

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
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("FAILED_LOGIN"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("wronguser"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains(AuditMessage.UTC_TIMESTAMP));
        Assert.assertFalse(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        validateMsgs(TestAuditlogImpl.messages);
    }

    public void testUnknownAuthorization() throws Exception {

        HttpResponse response = rh.executeGetRequest("", encodeBasicHeader("unknown", "unknown"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("FAILED_LOGIN"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("Basic dW5rbm93bjp1bmtub3du"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(AuditMessage.UTC_TIMESTAMP));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        validateMsgs(TestAuditlogImpl.messages);
    }

    public void testUnauthenticated() throws Exception {

        /// testUnauthenticated
        HttpResponse response = rh.executeGetRequest("_search");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(1500);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditLogImpl.contains("FAILED_LOGIN"));
        Assert.assertTrue(auditLogImpl.contains("<NONE>"));
        Assert.assertTrue(auditLogImpl.contains("/_search"));
        Assert.assertTrue(auditLogImpl.contains(AuditMessage.UTC_TIMESTAMP));
        Assert.assertFalse(auditLogImpl.contains("AUTHENTICATED"));
        validateMsgs(TestAuditlogImpl.messages);

    }

    public void testJustAuthenticated() throws Exception {
        HttpResponse response = rh.executeGetRequest("", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertEquals(0, TestAuditlogImpl.messages.size());
        validateMsgs(TestAuditlogImpl.messages);
    }

    public void testSecurityIndexAttempt() throws Exception {

        HttpResponse response = rh.executePutRequest(".opendistro_security/_doc/0", "{}", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("OPENDISTRO_SECURITY_INDEX_ATTEMPT"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("admin"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(AuditMessage.UTC_TIMESTAMP));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertEquals(2, TestAuditlogImpl.messages.size());
        validateMsgs(TestAuditlogImpl.messages);
    }

    public void testBadHeader() throws Exception {

        HttpResponse response = rh.executeGetRequest(
            "",
            new BasicHeader("_opendistro_security_bad", "bad"),
            encodeBasicHeader("admin", "admin")
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertFalse(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("AUTHENTICATED"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("BAD_HEADERS"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString(), TestAuditlogImpl.sb.toString().contains("_opendistro_security_bad"));
        Assert.assertEquals(TestAuditlogImpl.sb.toString(), 1, TestAuditlogImpl.messages.size());
        validateMsgs(TestAuditlogImpl.messages);
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
        validateMsgs(TestAuditlogImpl.messages);
    }

    public void testMsearch() throws Exception {

        String msearch = "{\"index\":\"sf\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":0,\"query\":{\"match_all\":{}}}"
            + System.lineSeparator()
            + "{\"index\":\"sf\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":0,\"query\":{\"match_all\":{}}}"
            + System.lineSeparator();

        // msaerch
        HttpResponse response = rh.executePostRequest("_msearch?pretty", msearch, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(response.getStatusReason(), HttpStatus.SC_OK, response.getStatusCode());
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditLogImpl, auditLogImpl.contains("indices:data/read/msearch"));
        Assert.assertTrue(auditLogImpl, auditLogImpl.contains("indices:data/read/search"));
        Assert.assertTrue(auditLogImpl, auditLogImpl.contains("match_all"));
        Assert.assertTrue(auditLogImpl.contains("audit_trace_task_id"));
        Assert.assertEquals(auditLogImpl, 4, TestAuditlogImpl.messages.size());
        Assert.assertFalse(auditLogImpl.toLowerCase().contains("authorization"));
        validateMsgs(TestAuditlogImpl.messages);
    }

    public void testBulkAuth() throws Exception {

        // testBulkAuth
        String bulkBody = "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value1\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"worf\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            +

            "{ \"update\" : {\"_id\" : \"1\", \"_index\" : \"test\"} }"
            + System.lineSeparator()
            + "{ \"doc\" : {\"field\" : \"valuex\"} }"
            + System.lineSeparator()
            + "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"create\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value3x\" }"
            + System.lineSeparator();

        HttpResponse response = rh.executePostRequest("_bulk", bulkBody, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"errors\":false"));
        Assert.assertTrue(response.getBody().contains("\"status\":201"));
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditLogImpl.contains("indices:admin/auto_create"));
        Assert.assertTrue(auditLogImpl.contains("indices:data/write/bulk"));
        Assert.assertTrue(auditLogImpl.contains("IndexRequest"));
        Assert.assertTrue(auditLogImpl.contains("audit_trace_task_parent_id"));
        Assert.assertTrue(auditLogImpl.contains("audit_trace_task_id"));
        // may vary because we log shardrequests which are not predictable here
        Assert.assertTrue(TestAuditlogImpl.messages.size() >= 17);
        validateMsgs(TestAuditlogImpl.messages);
    }

    public void testBulkNonAuth() throws Exception {

        String bulkBody = "{ \"index\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value1\" }"
            + System.lineSeparator()
            + "{ \"index\" : { \"_index\" : \"worf\", \"_id\" : \"2\" } }"
            + System.lineSeparator()
            + "{ \"field2\" : \"value2\" }"
            + System.lineSeparator()
            +

            "{ \"update\" : {\"_id\" : \"1\", \"_index\" : \"test\"} }"
            + System.lineSeparator()
            + "{ \"doc\" : {\"field\" : \"valuex\"} }"
            + System.lineSeparator()
            + "{ \"delete\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"create\" : { \"_index\" : \"test\", \"_id\" : \"1\" } }"
            + System.lineSeparator()
            + "{ \"field1\" : \"value3x\" }"
            + System.lineSeparator();

        HttpResponse response = rh.executePostRequest("_bulk", bulkBody, encodeBasicHeader("worf", "worf"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"errors\":true"));
        Assert.assertTrue(response.getBody().contains("\"status\":200"));
        Assert.assertTrue(response.getBody().contains("\"status\":403"));
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditLogImpl.contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(auditLogImpl.contains("indices:data/write/bulk[s]"));
        Assert.assertTrue(auditLogImpl.contains("IndexRequest"));
        // may vary because we log shardrequests which are not predictable here
        Assert.assertTrue(TestAuditlogImpl.messages.size() >= 7);
        validateMsgs(TestAuditlogImpl.messages);
    }

    public void testUpdateSettings() throws Exception {

        String json = "{"
            + "\"persistent\" : {"
            + "\"indices.recovery.*\" : null"
            + "},"
            + "\"transient\" : {"
            + "\"indices.recovery.*\" : null"
            + "}"
            + "}";

        String expectedRequestBodyLog =
            "{\\\"persistent_settings\\\":{\\\"indices\\\":{\\\"recovery\\\":{\\\"*\\\":null}}},\\\"transient_settings\\\":{\\\"indices\\\":{\\\"recovery\\\":{\\\"*\\\":null}}}}";

        HttpResponse response = rh.executePutRequest("_cluster/settings", json, encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditLogImpl.contains("AUTHENTICATED"));
        Assert.assertTrue(auditLogImpl.contains("cluster:admin/settings/update"));
        Assert.assertTrue(auditLogImpl.contains(expectedRequestBodyLog));
        // may vary because we log may hit cluster manager directly or not
        Assert.assertTrue(TestAuditlogImpl.messages.size() > 1);
        validateMsgs(TestAuditlogImpl.messages);
    }

    @Test
    public void testIndexPattern() throws Exception {

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", "internal_opensearch")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
            .put("plugins.security.audit.threadpool.size", 10) // must be greater 0
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

        TestAuditlogImpl.clear();

        HttpResponse response = rh.executeGetRequest("sf/_search?pretty", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditLogImpl.contains("starfleet_academy"));
        Assert.assertTrue(auditLogImpl.contains("starfleet_library"));
        Assert.assertTrue(auditLogImpl.contains("starfleet"));
        Assert.assertTrue(auditLogImpl.contains("sf"));
        Assert.assertEquals(2, TestAuditlogImpl.messages.size());
        validateMsgs(TestAuditlogImpl.messages);
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

        try (Client tc = getClient()) {
            for (int i = 0; i < 3; i++)
                tc.index(
                    new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
                ).actionGet();
        }

        TestAuditlogImpl.clear();

        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        int start = res.getBody().indexOf("_scroll_id") + 15;
        String scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start + 1));
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest(
                "/_search/scroll?pretty=true",
                "{\"scroll_id\" : \"" + scrollid + "\"}",
                encodeBasicHeader("admin", "admin")
            )).getStatusCode()
        );
        Assert.assertEquals(4, TestAuditlogImpl.messages.size());

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        start = res.getBody().indexOf("_scroll_id") + 15;
        scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start + 1));
        TestAuditlogImpl.clear();
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            (res = rh.executePostRequest(
                "/_search/scroll?pretty=true",
                "{\"scroll_id\" : \"" + scrollid + "\"}",
                encodeBasicHeader("admin2", "admin")
            )).getStatusCode()
        );
        Thread.sleep(1000);
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditLogImpl.contains("InternalScrollSearchRequest"));
        Assert.assertTrue(auditLogImpl.contains("MISSING_PRIVILEGES"));
        Assert.assertTrue(TestAuditlogImpl.messages.size() > 2);
        validateMsgs(TestAuditlogImpl.messages);
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

        try (Client tc = getClient()) {
            for (int i = 0; i < 3; i++)
                tc.index(
                    new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
                ).actionGet();
            tc.admin()
                .indices()
                .aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().alias("thealias").index("vulcangov")))
                .actionGet();
        }

        TestAuditlogImpl.clear();
        HttpResponse response = rh.executeGetRequest("thealias/_search?pretty", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditLogImpl.contains("thealias"));
        Assert.assertTrue(auditLogImpl.contains("audit_trace_resolved_indices"));
        Assert.assertTrue(auditLogImpl.contains("vulcangov"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        validateMsgs(TestAuditlogImpl.messages);
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
        HttpResponse response = rh.executeGetRequest(
            "_search?pretty",
            new BasicHeader("_opendistro_security_user", "xxx"),
            encodeBasicHeader("admin", "admin")
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertFalse(auditLogImpl.contains("YWRtaW46YWRtaW4"));
        Assert.assertTrue(auditLogImpl.contains("BAD_HEADERS"));
        Assert.assertTrue(auditLogImpl.contains("xxx"));
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        validateMsgs(TestAuditlogImpl.messages);
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

        try (Client tc = getClient()) {
            tc.admin().indices().create(new CreateIndexRequest("index1")).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("index2")).actionGet();
        }

        TestAuditlogImpl.clear();

        HttpResponse response = rh.executeDeleteRequest("index1?pretty", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executePostRequest("index2/_close?pretty", "", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        String auditLogImpl = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditLogImpl.contains("indices:admin/close"));
        Assert.assertTrue(auditLogImpl.contains("indices:admin/delete"));
        Assert.assertTrue(auditLogImpl, TestAuditlogImpl.messages.size() >= 2);
        validateMsgs(TestAuditlogImpl.messages);
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

        try (Client tc = getClient()) {
            for (int i = 0; i < 3; i++)
                tc.index(
                    new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)
                ).actionGet();
        }

        TestAuditlogImpl.clear();

        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest(
                "/vulcango*/_delete_by_query?refresh=true&wait_for_completion=true&pretty=true",
                "{\"query\" : {\"match_all\" : {}}}",
                encodeBasicHeader("admin", "admin")
            )).getStatusCode()
        );
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
        rh.executePutRequest(
            "/twitter",
            "{\"settings\":{\"index\":{\"number_of_shards\":3,\"number_of_replicas\":2}}}",
            encodeBasicHeader("admin", "admin")
        );
        String auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("\"audit_category\" : \"INDEX_EVENT\""));
        Assert.assertTrue(auditlogs.contains("\"audit_transport_request_type\" : \"CreateIndexRequest\","));
        Assert.assertTrue(
            auditlogs.contains(
                "\"audit_request_body\" : \"{\\\"index\\\":{\\\"number_of_shards\\\":\\\"3\\\",\\\"number_of_replicas\\\":\\\"2\\\"}}\""
            )
        );

        // test update index
        TestAuditlogImpl.clear();
        rh.executePutRequest("/twitter/_settings", "{\"index\":{\"number_of_replicas\":1}}", encodeBasicHeader("admin", "admin"));
        auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("\"audit_category\" : \"INDEX_EVENT\""));
        Assert.assertTrue(auditlogs.contains("\"audit_transport_request_type\" : \"UpdateSettingsRequest\","));
        Assert.assertTrue(auditlogs.contains("\"audit_request_body\" : \"{\\\"index\\\":{\\\"number_of_replicas\\\":\\\"1\\\"}}\""));

        // test put mapping
        TestAuditlogImpl.clear();
        rh.executePutRequest(
            "/twitter/_mapping",
            "{\"properties\":{\"message\":{\"type\":\"keyword\"}}}",
            encodeBasicHeader("admin", "admin")
        );
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

    private String messageRestRequestMethod(AuditMessage msg) {
        return msg.getAsMap().get("audit_rest_request_method").toString();
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
        List<AuditMessage> messages;

        // test GET
        messages = TestAuditlogImpl.doThenWaitForMessages(() -> { rh.executeGetRequest("test", adminHeader); }, 1);
        Assert.assertEquals(GET, messages.get(0).getRequestMethod());

        // test PUT
        messages = TestAuditlogImpl.doThenWaitForMessages(() -> { rh.executePutRequest("test/_doc/0", "{}", adminHeader); }, 1);
        Assert.assertEquals(PUT, messages.get(0).getRequestMethod());

        // test DELETE
        messages = TestAuditlogImpl.doThenWaitForMessages(() -> { rh.executeDeleteRequest("test", adminHeader); }, 1);
        Assert.assertEquals(DELETE, messages.get(0).getRequestMethod());

        // test POST
        messages = TestAuditlogImpl.doThenWaitForMessages(() -> { rh.executePostRequest("test/_doc", "{}", adminHeader); }, 1);
        Assert.assertEquals(POST, messages.get(0).getRequestMethod());

        // test PATCH
        messages = TestAuditlogImpl.doThenWaitForMessages(() -> { rh.executePatchRequest("/_opendistro/_security/api/audit", "[]"); }, 1);
        Assert.assertEquals(PATCH, messages.get(0).getRequestMethod());

        // test MISSING_PRIVILEGES
        // admin does not have REST role here
        messages = TestAuditlogImpl.doThenWaitForMessages(
            () -> { rh.executePatchRequest("/_opendistro/_security/api/audit", "[]", adminHeader); },
            2
        );
        // The intital request is authenicated
        Assert.assertEquals(PATCH, messages.get(0).getRequestMethod());
        Assert.assertEquals(AuditCategory.AUTHENTICATED, messages.get(0).getCategory());
        // The secondary request does not have permissions
        Assert.assertEquals(PATCH, messages.get(1).getRequestMethod());
        Assert.assertEquals(AuditCategory.MISSING_PRIVILEGES, messages.get(1).getCategory());

        // test AUTHENTICATED
        messages = TestAuditlogImpl.doThenWaitForMessages(() -> { rh.executeGetRequest("test", adminHeader); }, 1);
        Assert.assertEquals(AuditCategory.AUTHENTICATED, messages.get(0).getCategory());
        Assert.assertEquals(GET, messages.get(0).getRequestMethod());

        // test FAILED_LOGIN
        messages = TestAuditlogImpl.doThenWaitForMessages(
            () -> { rh.executeGetRequest("test", encodeBasicHeader("random", "random")); },
            1
        );
        Assert.assertEquals(AuditCategory.FAILED_LOGIN, messages.get(0).getCategory());
        Assert.assertEquals(GET, messages.get(0).getRequestMethod());

        // test BAD_HEADERS
        messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            rh.executeGetRequest("test", new BasicHeader("_opendistro_security_user", "xxx"));
        }, 1);
        Assert.assertEquals(AuditCategory.BAD_HEADERS, messages.get(0).getCategory());
        Assert.assertEquals(GET, messages.get(0).getRequestMethod());
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
        rh.executePutRequest(
            "/_opendistro/_security/api/internalusers/test1",
            "{\"password\":\"new-pass\", \"backend_roles\":[], \"attributes\": {}}"
        );
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(expectedRequestBody));

        // test PATCH internal users API
        TestAuditlogImpl.clear();
        rh.executePatchRequest(
            "/_opendistro/_security/api/internalusers/test1",
            "[{\"op\":\"add\", \"path\":\"/password\", \"value\": \"test-pass\"}]"
        );
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(expectedRequestBody));

        // test PUT users API
        TestAuditlogImpl.clear();
        rh.executePutRequest(
            "/_opendistro/_security/api/user/test2",
            "{\"password\":\"new-pass\", \"backend_roles\":[], \"attributes\": {}}"
        );
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains(expectedRequestBody));
    }
}
