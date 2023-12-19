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
import java.util.stream.Collectors;

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
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl.MessagesNotFoundException;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.AnyOf.anyOf;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThrows;

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

        String search = "{"
            + "   \"_source\":["
            + "      \"Gender\""
            + "   ],"
            + "   \"from\":0,"
            + "   \"size\":3,"
            + "   \"query\":{"
            + "      \"term\":{"
            + "         \"Salary\": 300"
            + "      }"
            + "   }"
            + "}";

        final AuditMessage message = TestAuditlogImpl.doThenWaitForMessage(() -> {
            final HttpResponse response = rh.executePostRequest("_search?pretty", search, encodeBasicHeader("admin", "admin"));
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        });

        assertThat(message.getCategory(), equalTo(AuditCategory.COMPLIANCE_DOC_READ));
        assertThat(message.getRequestBody(), not(containsString("Designation")));
        assertThat(message.getRequestBody(), not(containsString("Salary")));
        assertThat(message.getRequestBody(), containsString("Gender"));

        validateMsgs(TestAuditlogImpl.messages);
    }

    @Test
    public void testComplianceEnable() throws Exception {
        Settings additionalSettings = Settings.builder().put("plugins.security.audit.type", TestAuditlogImpl.class.getName()).build();

        setup(additionalSettings);

        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";

        // watch emp for write
        AuditConfig auditConfig = new AuditConfig(
            true,
            AuditConfig.Filter.DEFAULT,
            ComplianceConfig.from(
                ImmutableMap.of("enabled", true, "write_watched_indices", Collections.singletonList("emp")),
                additionalSettings
            )
        );
        updateAuditConfig(AuditTestUtils.createAuditPayload(auditConfig));

        // make an event happen
        List<AuditMessage> messages;
        try {
            messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
                rh.executePutRequest("emp/_doc/0?refresh", "{\"Designation\" : \"CEO\", \"Gender\" : \"female\", \"Salary\" : 100}");
                rh.executeGetRequest("_cat/shards?v");
            }, 7);
        } catch (final MessagesNotFoundException ex) {
            // indices:admin/mapping/auto_put can be logged twice, this handles if they were not found
            assertThat("Too many missing audit log messages", ex.getMissingCount(), equalTo(2));
            messages = ex.getFoundMessages();
        }

        messages.stream()
            .filter(msg -> msg.getCategory().equals(AuditCategory.COMPLIANCE_DOC_WRITE))
            .findFirst()
            .orElseThrow(() -> new RuntimeException("Missing COMPLIANCE message"));

        final List<AuditMessage> indexCreation = messages.stream()
            .filter(msg -> "indices:admin/auto_create".equals(msg.getPrivilege()))
            .collect(Collectors.toList());
        assertThat(indexCreation.size(), equalTo(2));

        final List<AuditMessage> mappingCreation = messages.stream()
            .filter(msg -> "indices:admin/mapping/auto_put".equals(msg.getPrivilege()))
            .collect(Collectors.toList());
        assertThat(mappingCreation.size(), anyOf(equalTo(4), equalTo(2)));

        // disable compliance
        auditConfig = new AuditConfig(
            true,
            AuditConfig.Filter.DEFAULT,
            ComplianceConfig.from(
                ImmutableMap.of("enabled", false, "write_watched_indices", Collections.singletonList("emp")),
                additionalSettings
            )
        );
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
            // .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "emp")
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

        String search = "{}"
            + System.lineSeparator()
            + "{"
            + "   \"_source\":["
            + "      \"Gender\""
            + "   ],"
            + "   \"from\":0,"
            + "   \"size\":3,"
            + "   \"query\":{"
            + "      \"term\":{"
            + "         \"Salary\": 300"
            + "      }"
            + "   }"
            + "}"
            + System.lineSeparator()
            +

            "{}"
            + System.lineSeparator()
            + "{"
            + "   \"_source\":["
            + "      \"Designation\""
            + "   ],"
            + "   \"from\":0,"
            + "   \"size\":3,"
            + "   \"query\":{"
            + "      \"term\":{"
            + "         \"Salary\": 200"
            + "      }"
            + "   }"
            + "}"
            + System.lineSeparator();

        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            HttpResponse response = rh.executePostRequest("_msearch?pretty", search, encodeBasicHeader("admin", "admin"));
            assertNotContains(response, "*exception*");
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        }, 2);

        final AuditMessage desginationMsg = messages.stream()
            .filter(msg -> msg.getRequestBody().contains("Designation"))
            .findFirst()
            .orElseThrow();
        assertThat(desginationMsg.getCategory(), equalTo(AuditCategory.COMPLIANCE_DOC_READ));
        assertThat(desginationMsg.getRequestBody(), containsString("Designation"));
        assertThat(desginationMsg.getRequestBody(), not(containsString("Salary")));

        final AuditMessage genderMsg = messages.stream().filter(msg -> msg.getRequestBody().contains("Gender")).findFirst().orElseThrow();
        assertThat(genderMsg.getCategory(), equalTo(AuditCategory.COMPLIANCE_DOC_READ));
        assertThat(genderMsg.getRequestBody(), containsString("Gender"));
        assertThat(genderMsg.getRequestBody(), not(containsString("Salary")));

        validateMsgs(messages);
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

        final List<String> expectedDocumentsTypes = List.of(
            "config",
            "actiongroups",
            "internalusers",
            "roles",
            "rolesmapping",
            "tenants",
            "audit"
        );
        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            try (RestHighLevelClient restHighLevelClient = getRestClient(clusterInfo, "kirk-keystore.jks", "truststore.jks")) {
                for (IndexRequest ir : new DynamicSecurityConfig().setSecurityRoles("roles_2.yml").getDynamicConfig(getResourceFolder())) {
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

        final List<String> documentIds = messages.stream().map(AuditMessage::getDocId).distinct().collect(Collectors.toList());
        assertThat(documentIds, equalTo(expectedDocumentsTypes));

        messages.stream().collect(Collectors.groupingBy(AuditMessage::getDocId)).entrySet().forEach((e) -> {
            final String docId = e.getKey();
            final List<AuditMessage> messagesByDocId = e.getValue();
            assertThat(
                "Doc " + docId + " should have a read/write config message",
                messagesByDocId.stream().map(AuditMessage::getCategory).collect(Collectors.toList()),
                equalTo(List.of(AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE, AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ))
            );
        });

        validateMsgs(messages);
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

        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            try {
                setup(additionalSettings);
            } catch (final Exception ex) {
                throw new RuntimeException(ex);
            }

            try (Client tc = getClient()) {
                for (IndexRequest ir : new DynamicSecurityConfig().setSecurityRoles("roles_2.yml").getDynamicConfig(getResourceFolder())) {
                    tc.index(ir).actionGet();
                }
            }

            final HttpResponse response = rh.executeGetRequest("_search?pretty", encodeBasicHeader("admin", "admin"));
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        }, 4);

        // Record the updated config, and then for each node record that the config was updated
        assertThat(messages.get(0).getCategory(), equalTo(AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE));
        assertThat(messages.get(1).getCategory(), equalTo(AuditCategory.COMPLIANCE_EXTERNAL_CONFIG));
        assertThat(messages.get(2).getCategory(), equalTo(AuditCategory.COMPLIANCE_EXTERNAL_CONFIG));
        assertThat(messages.get(3).getCategory(), equalTo(AuditCategory.COMPLIANCE_EXTERNAL_CONFIG));

        // Make sure that the config update messsages are for each node in the cluster
        assertThat(messages.get(1).getNodeId(), not(equalTo(messages.get(2).getNodeId())));
        assertThat(messages.get(2).getNodeId(), not(equalTo(messages.get(3).getNodeId())));

        validateMsgs(messages);
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
            .put(
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                "humanresources,Designation,FirstName,LastName"
            )
            .build();

        setup(additionalSettings);

        try (Client tc = getClient()) {
            tc.prepareIndex("humanresources").setRefreshPolicy(RefreshPolicy.IMMEDIATE).setSource("Age", 456).execute().actionGet();
        }

        final MessagesNotFoundException ex1 = assertThrows(MessagesNotFoundException.class, () -> {
            TestAuditlogImpl.doThenWaitForMessage(() -> {
                final String body = "{\"doc\": {\"Age\":123}}";
                final HttpResponse response = rh.executePostRequest(
                    "humanresources/_doc/100?pretty",
                    body,
                    encodeBasicHeader("admin", "admin")
                );
                Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
            });
        });
        assertThat(ex1.getMissingCount(), equalTo(1));

        final MessagesNotFoundException ex2 = assertThrows(MessagesNotFoundException.class, () -> {
            TestAuditlogImpl.doThenWaitForMessage(() -> {
                final String body = "{\"doc\": {\"Age\":456}}";
                final HttpResponse response = rh.executePostRequest(
                    "humanresources/_update/100?pretty",
                    body,
                    encodeBasicHeader("admin", "admin")
                );
                Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            });
        });
        assertThat(ex2.getMissingCount(), equalTo(1));

        Assert.assertTrue(TestAuditlogImpl.messages.isEmpty());
        validateMsgs(TestAuditlogImpl.messages);
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
            tc.prepareIndex("humanresources").setRefreshPolicy(RefreshPolicy.IMMEDIATE).setSource("Age", 456).execute().actionGet();
        }

        TestAuditlogImpl.doThenWaitForMessage(() -> {
            final String body = "{\"doc\": {\"Age\":123}}";
            final HttpResponse response = rh.executePostRequest(
                "humanresources/_doc/100?pretty",
                body,
                encodeBasicHeader("admin", "admin")
            );
            Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        });
        Assert.assertTrue(TestAuditlogImpl.sb.toString().split(".*audit_compliance_diff_content.*replace.*").length == 1);

        TestAuditlogImpl.doThenWaitForMessage(() -> {
            final String body = "{\"doc\": {\"Age\":555}}";
            final HttpResponse response = rh.executePostRequest(
                "humanresources/_update/100?pretty",
                body,
                encodeBasicHeader("admin", "admin")
            );
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        });
        Assert.assertTrue(TestAuditlogImpl.sb.toString().split(".*audit_compliance_diff_content.*replace.*").length == 1);
    }
}
