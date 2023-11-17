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

import java.util.List;
import java.util.stream.Collectors;

import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.fail;

public class RestApiComplianceAuditlogTest extends AbstractAuditlogiUnitTest {

    @Test
    public void testRestApiRolesEnabled() throws Exception {

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .build();

        setup(additionalSettings);
        Thread.sleep(100);
        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            String body = "{ \"password\":\"some new password\",\"backend_roles\":[\"role1\",\"role2\"] }";
            HttpResponse response = rh.executePutRequest(
                "_opendistro/_security/api/internalusers/compuser?pretty",
                body,
                encodeBasicHeader("admin", "admin")
            );
            Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
            sleepOrFail();
        }, 1);
        validateMsgs(messages);

        assertThat(messages.get(0).toString(), containsString("UPDATE"));
    }

    @Test
    public void testRestApiRolesDisabled() throws Exception {

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .build();

        setup(additionalSettings);
        Thread.sleep(100);
        String body = "{ \"password\":\"some new password\",\"backend_roles\":[\"role1\",\"role2\"] }";

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            HttpResponse response = rh.executePutRequest("_opendistro/_security/api/internalusers/compuser?pretty", body);
            Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
            sleepOrFail();
        }, 1);
        validateMsgs(messages);
        assertThat(messages.get(0).toString(), containsString("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
    }

    @Test
    public void testRestApiRolesDisabledGet() throws Exception {

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .build();

        setup(additionalSettings);
        Thread.sleep(100);

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";
        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/rolesmapping/opendistro_security_all_access?pretty");
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            sleepOrFail();
        }, 1);
        validateMsgs(messages);
        assertThat(messages.get(0).toString(), containsString("audit_request_effective_user"));
        assertThat(messages.get(0).toString(), containsString("COMPLIANCE_INTERNAL_CONFIG_READ"));
    }

    @Test
    public void testAutoInit() throws Exception {

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .build();

        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            try {
                setup(additionalSettings);
                Thread.sleep(100);
            } catch (Exception ignore) {
                fail("Received unexpected exception during setup");
            }
        }, 4);

        validateMsgs(messages);
        String allMessages = messages.stream().map(AuditMessage::toString).collect(Collectors.joining(","));
        assertThat(allMessages, containsString("audit_request_effective_user"));
        assertThat(allMessages, containsString("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
        assertThat(allMessages, containsString("COMPLIANCE_EXTERNAL_CONFIG"));
    }

    @Test
    public void testRestApiNewUser() throws Exception {

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .build();

        setup(additionalSettings);
        Thread.sleep(100);

        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            String body = "{ \"password\":\"some new password\",\"backend_roles\":[\"role1\",\"role2\"] }";
            HttpResponse response = rh.executePutRequest(
                "_opendistro/_security/api/internalusers/compuser?pretty",
                body,
                encodeBasicHeader("admin", "admin")
            );
            Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());
            sleepOrFail();
        }, 1);
        validateMsgs(messages);
        assertThat(messages.get(0).toString(), containsString("audit_request_effective_user"));
        assertThat(messages.get(0).toString(), containsString("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
    }

    @Test
    public void testRestInternalConfigRead() throws Exception {

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .build();

        setup(additionalSettings);
        Thread.sleep(100);

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/internalusers/admin?pretty");
            String auditLogImpl = TestAuditlogImpl.sb.toString();
            Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            sleepOrFail();
            Assert.assertTrue(auditLogImpl.contains("COMPLIANCE_INTERNAL_CONFIG_READ"));
        }, 1);
        validateMsgs(messages);
        assertThat(messages.get(0).toString(), containsString("COMPLIANCE_INTERNAL_CONFIG_READ"));
    }

    @Test
    public void testBCryptHashRedaction() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
            .build();
        setup(settings);
        Thread.sleep(100);
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        // read internal users and verify no BCrypt hash is present in audit logs
        TestAuditlogImpl.doThenWaitForMessages(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers");
            sleepOrFail();
            Assert.assertEquals(1, TestAuditlogImpl.messages.size());
            Assert.assertFalse(AuditMessage.BCRYPT_HASH.matcher(TestAuditlogImpl.sb.toString()).matches());
        }, 1);

        // read internal user worf and verify no BCrypt hash is present in audit logs
        TestAuditlogImpl.doThenWaitForMessages(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers/worf");
            sleepOrFail();
            Assert.assertEquals(1, TestAuditlogImpl.messages.size());
            Assert.assertFalse(AuditMessage.BCRYPT_HASH.matcher(TestAuditlogImpl.sb.toString()).matches());
        }, 1);

        // create internal user and verify no BCrypt hash is present in audit logs
        TestAuditlogImpl.doThenWaitForMessages(() -> {
            rh.executePutRequest("/_opendistro/_security/api/internalusers/test", "{ \"password\":\"some new user password\"}");

            Assert.assertEquals(1, TestAuditlogImpl.messages.size());
            Assert.assertFalse(AuditMessage.BCRYPT_HASH.matcher(TestAuditlogImpl.sb.toString()).matches());
        }, 1);
    }

    private static void sleepOrFail() {
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            fail("Received unexpected exception");
        }
    }
}
