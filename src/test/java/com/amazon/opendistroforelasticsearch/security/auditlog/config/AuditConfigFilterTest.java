package com.amazon.opendistroforelasticsearch.security.auditlog.config;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.collect.ImmutableSet;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import static com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory.AUTHENTICATED;
import static com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;
import static com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory.BAD_HEADERS;
import static com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory.SSL_EXCEPTION;
import static com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory.FAILED_LOGIN;
import static com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory.MISSING_PRIVILEGES;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

public class AuditConfigFilterTest {

    @Test
    public void testDefault() {
        // arrange
        final Set<String> defaultIgnoredUser = Collections.singleton("kibanaserver");
        final EnumSet<AuditCategory> defaultDisabledCategories = EnumSet.of(AUTHENTICATED, GRANTED_PRIVILEGES);
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(Settings.EMPTY);
        // assert
        assertTrue(auditConfigFilter.isRestApiAuditEnabled());
        assertTrue(auditConfigFilter.isTransportApiAuditEnabled());
        assertTrue(auditConfigFilter.shouldLogRequestBody());
        assertTrue(auditConfigFilter.shouldResolveIndices());
        assertFalse(auditConfigFilter.shouldResolveBulkRequests());
        assertTrue(auditConfigFilter.shouldExcludeSensitiveHeaders());
        assertTrue(auditConfigFilter.getIgnoredAuditRequests().isEmpty());
        assertEquals(auditConfigFilter.getIgnoredAuditUsers(), defaultIgnoredUser);
        assertEquals(auditConfigFilter.getIgnoredComplianceUsersForRead(), defaultIgnoredUser);
        assertEquals(auditConfigFilter.getIgnoredComplianceUsersForWrite(), defaultIgnoredUser);
        assertEquals(auditConfigFilter.getDisabledRestCategories(), defaultDisabledCategories);
        assertEquals(auditConfigFilter.getDisabledTransportCategories(), defaultDisabledCategories);
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
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(settings);
        // assert
        assertFalse(auditConfigFilter.isRestApiAuditEnabled());
        assertFalse(auditConfigFilter.isTransportApiAuditEnabled());
        assertFalse(auditConfigFilter.shouldLogRequestBody());
        assertFalse(auditConfigFilter.shouldResolveIndices());
        assertTrue(auditConfigFilter.shouldResolveBulkRequests());
        assertFalse(auditConfigFilter.shouldExcludeSensitiveHeaders());
        assertEquals(auditConfigFilter.getIgnoredAuditUsers(), Collections.singleton("test-user"));
        assertEquals(auditConfigFilter.getIgnoredAuditRequests(), Collections.singleton("test-request"));
        assertEquals(auditConfigFilter.getIgnoredComplianceUsersForRead(), ImmutableSet.of("test-user-1", "test-user-2"));
        assertEquals(auditConfigFilter.getIgnoredComplianceUsersForWrite(), ImmutableSet.of("test-user-3", "test-user-4"));
        assertEquals(auditConfigFilter.getDisabledRestCategories(), EnumSet.of(BAD_HEADERS, SSL_EXCEPTION));
        assertEquals(auditConfigFilter.getDisabledTransportCategories(), EnumSet.of(FAILED_LOGIN, MISSING_PRIVILEGES));
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
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(settings);
        // assert
        assertTrue(auditConfigFilter.getIgnoredAuditUsers().isEmpty());
        assertTrue(auditConfigFilter.getIgnoredComplianceUsersForRead().isEmpty());
        assertTrue(auditConfigFilter.getIgnoredComplianceUsersForWrite().isEmpty());
        assertTrue(auditConfigFilter.getDisabledRestCategories().isEmpty());
        assertTrue(auditConfigFilter.getDisabledTransportCategories().isEmpty());
    }

    @Test
    public void testEmpty() {
        // arrange
        final Settings settings = Settings.builder()
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, Collections.emptyList())
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,  Collections.emptyList())
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                        Collections.emptyList())
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                        Collections.emptyList())
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                        Collections.emptyList())
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                        Collections.emptyList())
                .build();
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(settings);
        // assert
        assertTrue(auditConfigFilter.getIgnoredAuditUsers().isEmpty());
        assertTrue(auditConfigFilter.getIgnoredComplianceUsersForRead().isEmpty());
        assertTrue(auditConfigFilter.getIgnoredComplianceUsersForWrite().isEmpty());
        assertTrue(auditConfigFilter.getDisabledRestCategories().isEmpty());
        assertTrue(auditConfigFilter.getDisabledTransportCategories().isEmpty());
    }
}
