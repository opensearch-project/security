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

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

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

        setupAndReturnAuditMessages(additionalSettings);
        final AuditMessage message = TestAuditlogImpl.doThenWaitForMessage(() -> {
            String body = "{ \"password\":\"some new password\",\"backend_roles\":[\"role1\",\"role2\"] }";
            HttpResponse response = rh.executePutRequest(
                "_opendistro/_security/api/internalusers/compuser?pretty",
                body,
                encodeBasicHeader("admin", "admin")
            );
            assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));
        });
        validateMsgs(List.of(message));

        assertThat(message.toString(), containsString("UPDATE"));
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

        setupAndReturnAuditMessages(additionalSettings);
        String body = "{ \"password\":\"some new password\",\"backend_roles\":[\"role1\",\"role2\"] }";

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        final AuditMessage message = TestAuditlogImpl.doThenWaitForMessage(() -> {
            HttpResponse response = rh.executePutRequest("_opendistro/_security/api/internalusers/compuser?pretty", body);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));
        });
        validateMsgs(List.of(message));
        assertThat(message.toString(), containsString("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
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

        setupAndReturnAuditMessages(additionalSettings);

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";
        final AuditMessage message = TestAuditlogImpl.doThenWaitForMessage(() -> {
            HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/rolesmapping/opendistro_security_all_access?pretty");
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        });
        validateMsgs(List.of(message));
        assertThat(message.toString(), containsString("audit_request_effective_user"));
        assertThat(message.toString(), containsString("COMPLIANCE_INTERNAL_CONFIG_READ"));
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

        final List<AuditMessage> messages = setupAndReturnAuditMessages(additionalSettings);

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

        setupAndReturnAuditMessages(additionalSettings);

        final AuditMessage message = TestAuditlogImpl.doThenWaitForMessage(() -> {
            String body = "{ \"password\":\"some new password\",\"backend_roles\":[\"role1\",\"role2\"] }";
            HttpResponse response = rh.executePutRequest(
                "_opendistro/_security/api/internalusers/compuser?pretty",
                body,
                encodeBasicHeader("admin", "admin")
            );
            assertThat(response.getBody(), response.getStatusCode(), is(HttpStatus.SC_CREATED));
        });
        validateMsgs(List.of(message));
        assertThat(message.toString(), containsString("audit_request_effective_user"));
        assertThat(message.toString(), containsString("COMPLIANCE_INTERNAL_CONFIG_WRITE"));
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

        setupAndReturnAuditMessages(additionalSettings);

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        final AuditMessage message = TestAuditlogImpl.doThenWaitForMessage(() -> {
            HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/internalusers/admin?pretty");
            String auditLogImpl = TestAuditlogImpl.sb.toString();
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            Assert.assertTrue(auditLogImpl.contains("COMPLIANCE_INTERNAL_CONFIG_READ"));
        });
        validateMsgs(List.of(message));
        assertThat(message.toString(), containsString("COMPLIANCE_INTERNAL_CONFIG_READ"));
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
        setupAndReturnAuditMessages(settings);
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        // read internal users and verify no BCrypt hash is present in audit logs
        final AuditMessage message1 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers");
        });

        Assert.assertFalse(AuditMessage.HASH_REGEX_PATTERN.matcher(message1.toString()).matches());

        // read internal user worf and verify no BCrypt hash is present in audit logs
        final AuditMessage message2 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers/worf");
            Assert.assertFalse(AuditMessage.HASH_REGEX_PATTERN.matcher(TestAuditlogImpl.sb.toString()).matches());
        });

        Assert.assertFalse(AuditMessage.HASH_REGEX_PATTERN.matcher(message2.toString()).matches());

        // create internal user and verify no BCrypt hash is present in audit logs
        final AuditMessage message3 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executePutRequest("/_opendistro/_security/api/internalusers/test", "{ \"password\":\"some new user password\"}");
        });

        Assert.assertFalse(AuditMessage.HASH_REGEX_PATTERN.matcher(message3.toString()).matches());
    }

    @Test
    public void testPBKDF2HashRedaction() {
        final Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, "opendistro_security_all_access")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
            .put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.PBKDF2)
            .build();
        final DynamicSecurityConfig securityConfig = new DynamicSecurityConfig().setSecurityInternalUsers("internal_users_pbkdf2.yml");
        setupAndReturnAuditMessages(settings, securityConfig);
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        // read internal users and verify no PBKDF2 hash is present in audit logs
        final AuditMessage message1 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers");
        });

        Assert.assertFalse(
            message1.toString()
                .contains(
                    "$3$1331439861760512$wBFrJJIAokWuJxlO6BQPLashXgznvR4tRmXk3aEy9SpHWrb9kFjPPLByZZzMLBNQFjhepgbngYh7RfMh8TrPLw==$vqGlzGsxqGf9TgfxhORjdoqRFB3npvBd9B0GAtBMg9mD2zBbSTohRYlOxUL7UQLma66zZdD67c4RNE9BKelabw=="
                )
        );
        Assert.assertTrue(message1.toString().contains("__HASH__"));

        // read internal user and verify no PBKDF2 hash is present in audit logs
        final AuditMessage message2 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers/user1");
        });

        Assert.assertFalse(
            message2.toString()
                .contains(
                    "$3$1331439861760512$wBFrJJIAokWuJxlO6BQPLashXgznvR4tRmXk3aEy9SpHWrb9kFjPPLByZZzMLBNQFjhepgbngYh7RfMh8TrPLw==$vqGlzGsxqGf9TgfxhORjdoqRFB3npvBd9B0GAtBMg9mD2zBbSTohRYlOxUL7UQLma66zZdD67c4RNE9BKelabw=="
                )
        );
        Assert.assertTrue(message2.toString().contains("__HASH__"));

        // create internal user and verify no PBKDF2 hash is present in audit logs
        final AuditMessage message3 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executePutRequest("/_opendistro/_security/api/internalusers/test", "{ \"password\":\"some new user password\"}");
        });

        Assert.assertFalse(
            message3.toString()
                .contains(
                    "$3$1331439861760512$wBFrJJIAokWuJxlO6BQPLashXgznvR4tRmXk3aEy9SpHWrb9kFjPPLByZZzMLBNQFjhepgbngYh7RfMh8TrPLw==$vqGlzGsxqGf9TgfxhORjdoqRFB3npvBd9B0GAtBMg9mD2zBbSTohRYlOxUL7UQLma66zZdD67c4RNE9BKelabw=="
                )
        );
        Assert.assertTrue(message3.toString().contains("__HASH__"));

        // test with various users and different PBKDF2 hash formats to make sure they all get redacted
        final AuditMessage message4 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers", encodeBasicHeader("user1", "user1"));
        });

        Assert.assertFalse(
            message4.toString()
                .contains(
                    "$1$4294967296128$VmnDMbQ4wLiFUq178RKvj+EYfdb3Q26qCiDcJDoCxpYnKpyuG0JhTC2wpUkMUveV5RmBFzldKQkdqZEfE0XAgg==$9u3aMWc6VP2oGkXei7UaXA=="
                )
        );
        Assert.assertTrue(message4.toString().contains("__HASH__"));

        final AuditMessage message5 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers", encodeBasicHeader("user2", "user2"));
        });

        Assert.assertFalse(
            message5.toString()
                .contains(
                    "$2$214748364800224$eQgqv2RI6yo95yeVnM5sfwUCwxHo6re0w+wpx6ZqZtHQV+dzlyP6YFitjNG2mlaTkg0pR56xArQaAgapdVcBQQ==$tGHWhoc83cd5nZ7QIZKPORjW/N5jklhYhRgXpw=="
                )
        );
        Assert.assertTrue(message5.toString().contains("__HASH__"));

        final AuditMessage message6 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers", encodeBasicHeader("user3", "user3"));
        });

        Assert.assertFalse(
            message6.toString()
                .contains(
                    "$3$322122547200256$5b3wEAsMc05EZFxfncCUfZRERgvbwlBhYXd5vVR14kNJtmhXSpYMzydRZxO9096IPTkc47doH4hIdKX6LTguLg==$oQQvAtUyOC6cwdAYi5WeIM7rGUN9l3IdJ9y2RNxZCWo="
                )
        );
        Assert.assertTrue(message6.toString().contains("__HASH__"));

        final AuditMessage message7 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers", encodeBasicHeader("user4", "user4"));
        });

        Assert.assertFalse(
            message7.toString()
                .contains(
                    "$4$429496729600384$+SNSgbZD67a1bd92iuEiHCq5pvvrCx3HrNIf5hbGIJdxgXegpWilpB6vUGvYigegAUzZqE9iIsL4pSJztUNJYw==$lTxZ7tax6dBQ0r4qPJpc8d7YuoTBiUujY9HJeAZvARXMjIgvnJwa6FeYugttOKc0"
                )
        );
        Assert.assertTrue(message7.toString().contains("__HASH__"));

        final AuditMessage message8 = TestAuditlogImpl.doThenWaitForMessage(() -> {
            rh.executeGetRequest("/_opendistro/_security/api/internalusers", encodeBasicHeader("user5", "user5"));
        });

        Assert.assertFalse(
            message8.toString()
                .contains(
                    "$5$644245094400512$HQe/MOv/NAlgodNhqTmjqj5jGxBwG5xuRaxKwn7r4nlUba1kj/CYnpdFaXGvVeRxt2NLm8fbekS6NYonv358Ew==$1sDx+0tMbtGzU6jlQg/Dyt30Yxuy5RdNmP9B1EzMTxYWi8k1xg2gXLy7w1XbetEC8UD/lpyXJPlaoxXpsaADyA=="
                )
        );
        Assert.assertTrue(message8.toString().contains("__HASH__"));

    }

    private List<AuditMessage> setupAndReturnAuditMessages(Settings settings) {
        return setupAndReturnAuditMessages(settings, new DynamicSecurityConfig());
    }

    private List<AuditMessage> setupAndReturnAuditMessages(Settings settings, DynamicSecurityConfig dynamicSecurityConfig) {
        // When OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED is set to true, there is:
        // - 1 message with COMPLIANCE_INTERNAL_CONFIG_WRITE as category.
        // - 1 message with COMPLIANCE_EXTERNAL_CONFIG as category for each node.
        int numNodes = ClusterConfiguration.DEFAULT.getNodes();
        boolean externalConfigEnabled = settings.getAsBoolean(
            ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED,
            false
        );
        int expectedMessageCount = externalConfigEnabled ? (numNodes + 1) : 1;
        final List<AuditMessage> messages = TestAuditlogImpl.doThenWaitForMessages(() -> {
            try {
                setup(settings, dynamicSecurityConfig);
            } catch (final Exception ex) {
                throw new RuntimeException(ex);
            }
        }, expectedMessageCount);
        int complianceInternalConfigWriteCount = 0;
        int complianceExternalConfigCount = 0;
        for (AuditMessage message : messages) {
            if (AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE.equals(message.getCategory())) {
                complianceInternalConfigWriteCount++;
            } else if (AuditCategory.COMPLIANCE_EXTERNAL_CONFIG.equals(message.getCategory())) {
                complianceExternalConfigCount++;
            }
        }
        assertThat(complianceInternalConfigWriteCount, equalTo(1));
        if (externalConfigEnabled) {
            assertThat(complianceExternalConfigCount, equalTo(numNodes));
        }
        return messages;
    }

}
