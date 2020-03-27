package com.amazon.opendistroforelasticsearch.security.auditlog.config;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.collect.ImmutableSet;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import static com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory.*;
import static org.junit.Assert.*;

public class AuditConfigTest {

    @Test
    public void testDefault() {
        // arrange
        final Set<String> defaultIgnoredUser = Collections.singleton("kibanaserver");
        final EnumSet<AuditCategory> defaultDisabledCategories = EnumSet.of(AUTHENTICATED, GRANTED_PRIVILEGES);
        // act
        final AuditConfig auditConfig = AuditConfig.getConfig(Settings.EMPTY);
        // assert
        assertTrue(auditConfig.isRestAuditingEnabled());
        assertTrue(auditConfig.isTransportAuditingEnabled());
        assertTrue(auditConfig.shouldLogRequestBody());
        assertTrue(auditConfig.shouldResolveIndices());
        assertFalse(auditConfig.shouldResolveBulkRequests());
        assertTrue(auditConfig.shouldExcludeSensitiveHeaders());
        assertTrue(auditConfig.getIgnoredAuditRequests().isEmpty());
        assertEquals(auditConfig.getIgnoredAuditUsers(), defaultIgnoredUser);
        assertEquals(auditConfig.getIgnoredComplianceUsersForRead(), defaultIgnoredUser);
        assertEquals(auditConfig.getIgnoredComplianceUsersForWrite(), defaultIgnoredUser);
        assertEquals(auditConfig.getDisabledRestCategories(), defaultDisabledCategories);
        assertEquals(auditConfig.getDisabledTransportCategories(), defaultDisabledCategories);
        assertEquals(".opendistro_security", auditConfig.getOpendistrosecurityIndex());
    }

    @Test
    public void testConfig() {
        // arrange
        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, "test-index")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, "test-request")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "test-user")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                        "test-user-1", "test-user-2")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                        "test-user-3", "test-user-4")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                        BAD_HEADERS.toString(), SSL_EXCEPTION.toString())
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                        FAILED_LOGIN.toString(), MISSING_PRIVILEGES.toString())
                .build();
        // act
        final AuditConfig auditConfig = AuditConfig.getConfig(settings);
        // assert
        assertFalse(auditConfig.isRestAuditingEnabled());
        assertFalse(auditConfig.isTransportAuditingEnabled());
        assertFalse(auditConfig.shouldLogRequestBody());
        assertFalse(auditConfig.shouldResolveIndices());
        assertTrue(auditConfig.shouldResolveBulkRequests());
        assertFalse(auditConfig.shouldExcludeSensitiveHeaders());
        assertEquals(auditConfig.getIgnoredAuditUsers(), Collections.singleton("test-user"));
        assertEquals(auditConfig.getIgnoredAuditRequests(), Collections.singleton("test-request"));
        assertEquals(auditConfig.getIgnoredComplianceUsersForRead(), ImmutableSet.of("test-user-1", "test-user-2"));
        assertEquals(auditConfig.getIgnoredComplianceUsersForWrite(), ImmutableSet.of("test-user-3", "test-user-4"));
        assertEquals(auditConfig.getDisabledRestCategories(), EnumSet.of(BAD_HEADERS, SSL_EXCEPTION));
        assertEquals(auditConfig.getDisabledTransportCategories(), EnumSet.of(FAILED_LOGIN, MISSING_PRIVILEGES));
        assertEquals("test-index", auditConfig.getOpendistrosecurityIndex());
    }

    @Test
    public void testNone() {
        // arrange
        final Settings settings = Settings.builder()
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "NONE")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                        "NONE")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                        "NONE")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                        "None")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                        "none")
                .build();
        // act
        final AuditConfig auditConfig = AuditConfig.getConfig(settings);
        // assert
        assertTrue(auditConfig.getIgnoredAuditUsers().isEmpty());
        assertTrue(auditConfig.getIgnoredComplianceUsersForRead().isEmpty());
        assertTrue(auditConfig.getIgnoredComplianceUsersForWrite().isEmpty());
        assertTrue(auditConfig.getDisabledRestCategories().isEmpty());
        assertTrue(auditConfig.getDisabledTransportCategories().isEmpty());
    }
}
