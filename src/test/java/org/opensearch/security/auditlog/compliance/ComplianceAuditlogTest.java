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

package org.opensearch.security.auditlog.compliance;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import com.google.common.collect.ImmutableMap;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.AuditTestUtils;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl.MessagesNotFoundException;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class ComplianceAuditlogTest extends AbstractAuditlogiUnitTest {

    @Test
    public void testSourceFilter() throws Exception {
        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, "emp")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();

        setup(additionalSettings);
        final boolean sendAdminCertificate = rh.sendAdminCertificate;
        final String keystore = rh.keystore;
        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";
        rh.executePutRequest("emp/_doc/0?refresh", "{\"Designation\" : \"CEO\", \"Gender\" : \"female\", \"Salary\" : 100}", new Header[0]);
        rh.executePutRequest("emp/_doc/1?refresh", "{\"Designation\" : \"IT\", \"Gender\" : \"male\", \"Salary\" : 200}", new Header[0]);
        rh.executePutRequest("emp/_doc/2?refresh", "{\"Designation\" : \"IT\", \"Gender\" : \"female\", \"Salary\" : 300}", new Header[0]);
        rh.sendAdminCertificate = sendAdminCertificate;
        rh.keystore = keystore;

        String search = "{" +
                "   \"_source\":[" +
                "      \"Gender\""+
                "   ]," +
                "   \"from\":0," +
                "   \"size\":3," +
                "   \"query\":{" +
                "      \"term\":{" +
                "         \"Salary\": 300" +
                "      }" +
                "   }" +
                "}";

        final AuditMessage message = TestAuditlogImpl.doThenWaitForMessage(() -> {
            final HttpResponse response = rh.executePostRequest("_search?pretty", search, encodeBasicHeader("admin", "admin"));
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        });

        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_DOC_READ"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("Designation"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("Salary"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("Gender"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testComplianceEnable() throws Exception {
        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .build();

        setup(additionalSettings);

        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";

        // watch emp for write
        AuditConfig auditConfig = new AuditConfig(true, AuditConfig.Filter.DEFAULT , ComplianceConfig.from(ImmutableMap.of("enabled", true, "write_watched_indices", Collections.singletonList("emp")), additionalSettings));
        updateAuditConfig(AuditTestUtils.createAuditPayload(auditConfig));

        // make an event happen
        TestAuditlogImpl.doThenWaitForMessages(() -> {
            rh.executePutRequest("emp/_doc/0?refresh", "{\"Designation\" : \"CEO\", \"Gender\" : \"female\", \"Salary\" : 100}");
        }, 7);
        assertTrue(TestAuditlogImpl.messages.toString().contains("COMPLIANCE_DOC_WRITE"));
        // disable compliance
        auditConfig = new AuditConfig(true, AuditConfig.Filter.DEFAULT , ComplianceConfig.from(ImmutableMap.of("enabled", false, "write_watched_indices", Collections.singletonList("emp")), additionalSettings));
        updateAuditConfig(AuditTestUtils.createAuditPayload(auditConfig));

        // trigger an event that it not captured by the audit log
        final MessagesNotFoundException ex = assertThrows(MessagesNotFoundException.class, () -> {
            TestAuditlogImpl.doThenWaitForMessage(() -> {
                rh.executePutRequest("emp/_doc/1?refresh", "{\"Designation\" : \"CEO\", \"Gender\" : \"female\", \"Salary\" : 100}");
            });
        });
        assertThat(ex.getMissingCount(), equalTo(1));
    }

    @Test
    public void testSourceFilterMsearch() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                //.put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "emp")
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, "emp")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();

        setup(additionalSettings);
        final boolean sendAdminCertificate = rh.sendAdminCertificate;
        final String keystore = rh.keystore;
        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";
        rh.executePutRequest("emp/_doc/0?refresh", "{\"Designation\" : \"CEO\", \"Gender\" : \"female\", \"Salary\" : 100}", new Header[0]);
        rh.executePutRequest("emp/_doc/1?refresh", "{\"Designation\" : \"IT\", \"Gender\" : \"male\", \"Salary\" : 200}", new Header[0]);
        rh.executePutRequest("emp/_doc/2?refresh", "{\"Designation\" : \"IT\", \"Gender\" : \"female\", \"Salary\" : 300}", new Header[0]);
        rh.sendAdminCertificate = sendAdminCertificate;
        rh.keystore = keystore;

        String search = "{}"+System.lineSeparator()
                + "{" +
                "   \"_source\":[" +
                "      \"Gender\""+
                "   ]," +
                "   \"from\":0," +
                "   \"size\":3," +
                "   \"query\":{" +
                "      \"term\":{" +
                "         \"Salary\": 300" +
                "      }" +
                "   }" +
                "}"+System.lineSeparator()+

                "{}"+System.lineSeparator()
                + "{" +
                "   \"_source\":[" +
                "      \"Designation\""+
                "   ]," +
                "   \"from\":0," +
                "   \"size\":3," +
                "   \"query\":{" +
                "      \"term\":{" +
                "         \"Salary\": 200" +
                "      }" +
                "   }" +
                "}"+System.lineSeparator();

        TestAuditlogImpl.doThenWaitForMessages(() -> {
            HttpResponse response = rh.executePostRequest("_msearch?pretty", search, encodeBasicHeader("admin", "admin"));
            assertNotContains(response, "*exception*");
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        }, 2);
        System.out.println(TestAuditlogImpl.sb.toString());
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_DOC_READ"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("Salary"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("Gender"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("Designation"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testInternalConfig() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();

        setup(additionalSettings);

        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            try (RestHighLevelClient restHighLevelClient = getRestClient(clusterInfo, "kirk-keystore.jks", "truststore.jks")) {
                for (IndexRequest ir: new DynamicSecurityConfig().setSecurityRoles("roles_2.yml").getDynamicConfig(getResourceFolder())) {
                    restHighLevelClient.index(ir, RequestOptions.DEFAULT);
                    GetResponse getDocumentResponse = restHighLevelClient.get(new GetRequest(ir.index(), ir.id()), RequestOptions.DEFAULT);
                    assertThat(getDocumentResponse.isExists(), equalTo(true));
                }
            } catch (IOException ioe) {
                throw new RuntimeException("Unexpected exception", ioe);
            }

            HttpResponse response = rh.executeGetRequest("_search?pretty", encodeBasicHeader("admin", "admin"));
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }, 14);

        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_READ"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("anonymous_auth_enabled"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/read/suggest"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("internalusers"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("opendistro_security_all_access"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("indices:data/read/suggest"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("eyJzZWFyY2hndWFy"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("eyJBTEwiOlsiaW"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("eyJhZG1pbiI6e"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("eyJzZ19hb"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("eyJzZ19hbGx"));
        Assert.assertFalse(TestAuditlogImpl.sb.toString().contains("dvcmYiOnsiY2x"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("\\\"op\\\":\\\"remove\\\",\\\"path\\\":\\\"/opendistro_security_worf\\\""));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testExternalConfig() throws Exception {

        final Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();

        TestAuditlogImpl.doThenWaitForMessages(() -> {
            try {
                setup(additionalSettings);
            } catch (final Exception ex) {
                throw new RuntimeException(ex);
            }

            try (Client tc = getClient()) {
                for(IndexRequest ir: new DynamicSecurityConfig().setSecurityRoles("roles_2.yml").getDynamicConfig(getResourceFolder())) {
                    tc.index(ir).actionGet();
                }
            }

            final HttpResponse response = rh.executeGetRequest("_search?pretty", encodeBasicHeader("admin", "admin"));
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        }, 4);

        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("external_configuration"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("COMPLIANCE_EXTERNAL_CONFIG"));
        Assert.assertTrue(TestAuditlogImpl.sb.toString().contains("opensearch_yml"));
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testUpdate() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "finance")
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, "humanresources,Designation,FirstName,LastName")
                .build();

        setup(additionalSettings);


        try (Client tc = getClient()) {
            tc.prepareIndex("humanresources")
            .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .setSource("Age", 456)
            .execute()
            .actionGet();
        }

        final MessagesNotFoundException ex1 = assertThrows(MessagesNotFoundException.class, () -> {
            TestAuditlogImpl.doThenWaitForMessage(() -> {
                final String body = "{\"doc\": {\"Age\":123}}";
                final HttpResponse response =  rh.executePostRequest("humanresources/_doc/100?pretty", body, encodeBasicHeader("admin", "admin"));
                Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
            });
        });
        assertThat(ex1.getMissingCount(), equalTo(1));


        final MessagesNotFoundException ex2 = assertThrows(MessagesNotFoundException.class, () -> {
            TestAuditlogImpl.doThenWaitForMessage(() -> {
                final String body = "{\"doc\": {\"Age\":456}}";
                final HttpResponse response =  rh.executePostRequest("humanresources/_update/100?pretty", body, encodeBasicHeader("admin", "admin"));
                Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            });
        });
        assertThat(ex2.getMissingCount(), equalTo(1));

        Assert.assertTrue(TestAuditlogImpl.messages.isEmpty());
        Assert.assertTrue(validateMsgs(TestAuditlogImpl.messages));
    }

    @Test
    public void testWriteHistory() throws Exception {

        Settings additionalSettings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "humanresources")
                .build();

        setup(additionalSettings);

        try (Client tc = getClient()) {
            tc.prepareIndex("humanresources")
            .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .setSource("Age", 456)
            .execute()
            .actionGet();
        }

        TestAuditlogImpl.doThenWaitForMessage(() -> {
            final String body = "{\"doc\": {\"Age\":123}}";
            final HttpResponse response = rh.executePostRequest("humanresources/_doc/100?pretty", body, encodeBasicHeader("admin", "admin"));
            Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        });
        Assert.assertTrue(TestAuditlogImpl.sb.toString().split(".*audit_compliance_diff_content.*replace.*").length == 1);

        TestAuditlogImpl.doThenWaitForMessage(() -> {
            final String body = "{\"doc\": {\"Age\":555}}";
            final HttpResponse response = rh.executePostRequest("humanresources/_update/100?pretty", body, encodeBasicHeader("admin", "admin"));
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        });
        Assert.assertTrue(TestAuditlogImpl.sb.toString().split(".*audit_compliance_diff_content.*replace.*").length == 1);
    }
}
