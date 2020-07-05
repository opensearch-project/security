package com.amazon.opendistroforelasticsearch.security.auditlog.config;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableSet;
import org.elasticsearch.common.settings.Settings;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;

import static com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory.AUTHENTICATED;
import static com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

public class AuditConfigSerializeTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final WildcardMatcher DEFAULT_IGNORED_USER = WildcardMatcher.from(AuditConfig.DEFAULT_IGNORED_USERS_SET);

    @Before
    public void setUp() {
        InjectableValues.Std iv = new InjectableValues.Std();
        iv.addValue(Settings.class, Settings.EMPTY);
        objectMapper.setInjectableValues(iv);
    }

    @Test
    public void testDefaultSerialize() throws JsonProcessingException {
        // arrange
        final AuditConfig audit = new AuditConfig(true, null, null);
        // act
        final String json = objectMapper.writeValueAsString(audit);
        assertEquals("{" +
                "\"enabled\":true," +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":[\"GRANTED_PRIVILEGES\",\"AUTHENTICATED\"]," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":[\"GRANTED_PRIVILEGES\",\"AUTHENTICATED\"]," +
                    "\"resolve_bulk_requests\":false,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":[\"kibanaserver\"],\"ignore_requests\":[]}," +
                "\"compliance\":{" +
                    "\"enabled\":true," +
                    "\"external_config\":false,\"internal_config\":false," +
                    "\"read_metadata_only\":false,\"read_watched_fields\":{},\"read_ignore_users\":[\"kibanaserver\"]," +
                    "\"write_metadata_only\":false,\"write_log_diffs\":false,\"write_watched_indices\":[],\"write_ignore_users\":[\"kibanaserver\"]}" +
                "}", json);
    }

    @Test
    public void testDefaultDeserialize() throws IOException {
        // act
        final AuditConfig auditConfig = objectMapper.readValue("{}", AuditConfig.class);
        final AuditConfig.Filter audit = auditConfig.getFilter();
        final ComplianceConfig compliance = auditConfig.getCompliance();
        // assert
        assertTrue(audit.isRestApiAuditEnabled());
        assertEquals(audit.getDisabledRestCategories(), EnumSet.of(AuditCategory.AUTHENTICATED, AuditCategory.GRANTED_PRIVILEGES));
        assertTrue(audit.isTransportApiAuditEnabled());
        assertEquals(audit.getDisabledTransportCategories(), EnumSet.of(AuditCategory.AUTHENTICATED, AuditCategory.GRANTED_PRIVILEGES));
        assertFalse(audit.shouldResolveBulkRequests());
        assertTrue(audit.shouldLogRequestBody());
        assertTrue(audit.shouldResolveIndices());
        assertTrue(audit.shouldExcludeSensitiveHeaders());
        assertSame(WildcardMatcher.NONE, audit.getIgnoredAuditRequestsMatcher());
        assertEquals(DEFAULT_IGNORED_USER, audit.getIgnoredAuditUsersMatcher());
        assertFalse(compliance.shouldLogExternalConfig());
        assertFalse(compliance.shouldLogInternalConfig());
        assertFalse(compliance.shouldLogReadMetadataOnly());
        assertEquals(DEFAULT_IGNORED_USER, compliance.getIgnoredComplianceUsersForReadMatcher());
        assertFalse(compliance.shouldLogWriteMetadataOnly());
        assertFalse(compliance.shouldLogDiffsForWrite());
        assertEquals(DEFAULT_IGNORED_USER, compliance.getIgnoredComplianceUsersForWriteMatcher());
    }

    @Test
    public void testDeserialize() throws IOException {
        // arrange
        final String json = "{" +
                "\"enabled\":true," +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":[\"AUTHENTICATED\"]," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":[\"SSL_EXCEPTION\"]," +
                    "\"resolve_bulk_requests\":true,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":[\"test-user-1\"],\"ignore_requests\":[\"test-request\"]}," +
                "\"compliance\":{" +
                    "\"enabled\":true," +
                    "\"internal_config\":true,\"external_config\":true," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":{\"test-read-watch-field\":[\"test-field-1\"]},\"read_ignore_users\":[\"test-user-2\"]," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":true,\"write_watched_indices\":[\"test-write-watch-index\"],\"write_ignore_users\":[\"test-user-3\"]}" +
                "}";

        // act
        final AuditConfig auditConfig = objectMapper.readValue(json, AuditConfig.class);
        final AuditConfig.Filter audit = auditConfig.getFilter();
        final ComplianceConfig configCompliance = auditConfig.getCompliance();
        // assert
        assertTrue(audit.isRestApiAuditEnabled());
        assertEquals(audit.getDisabledRestCategories(), EnumSet.of(AuditCategory.AUTHENTICATED));
        assertTrue(audit.isTransportApiAuditEnabled());
        assertEquals(audit.getDisabledTransportCategories(), EnumSet.of(AuditCategory.SSL_EXCEPTION));
        assertTrue(audit.shouldResolveBulkRequests());
        assertTrue(audit.shouldLogRequestBody());
        assertTrue(audit.shouldResolveIndices());
        assertTrue(audit.shouldExcludeSensitiveHeaders());
        assertTrue(configCompliance.shouldLogExternalConfig());
        assertTrue(configCompliance.shouldLogInternalConfig());
        assertEquals(WildcardMatcher.from(Collections.singleton("test-user-1")), audit.getIgnoredAuditUsersMatcher());
        assertEquals(WildcardMatcher.from(Collections.singleton("test-request")), audit.getIgnoredAuditRequestsMatcher());
        assertTrue(configCompliance.shouldLogReadMetadataOnly());
        assertEquals(WildcardMatcher.from(Collections.singleton("test-user-2")), configCompliance.getIgnoredComplianceUsersForReadMatcher());
        assertEquals(Collections.singletonMap(WildcardMatcher.from("test-read-watch-field"), Collections.singleton("test-field-1")), configCompliance.getReadEnabledFields());
        assertTrue(configCompliance.shouldLogWriteMetadataOnly());
        assertFalse(configCompliance.shouldLogDiffsForWrite());
        assertEquals(WildcardMatcher.from(Collections.singleton("test-user-3")), configCompliance.getIgnoredComplianceUsersForWriteMatcher());
        assertEquals(WildcardMatcher.from("test-write-watch-index"), configCompliance.getWatchedWriteIndicesMatcher());
    }

    @Test
    public void testSerialize() throws IOException {
        // arrange
        final AuditConfig.Filter audit = new AuditConfig.Filter(true, true, true, true, true, true, ImmutableSet.of("ignore-user-1", "ignore-user-2"), ImmutableSet.of("ignore-request-1"), EnumSet.of(AuditCategory.FAILED_LOGIN, AuditCategory.GRANTED_PRIVILEGES), EnumSet.of(AUTHENTICATED));
        final ComplianceConfig compliance = new ComplianceConfig(true, true, true, true, Collections.singletonMap("test-read-watch-field-1", Collections.emptySet()), Collections.singleton("test-user-1"), true, false,Collections.singletonList("test-write-watch-index"), Collections.singleton("test-user-2"), Settings.EMPTY);
        final AuditConfig auditConfig = new AuditConfig(true, audit, compliance);
        // act
        final String json = objectMapper.writeValueAsString(auditConfig);
        // assert
        assertEquals("{" +
                "\"enabled\":true," +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":[\"FAILED_LOGIN\",\"GRANTED_PRIVILEGES\"]," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":[\"AUTHENTICATED\"]," +
                    "\"resolve_bulk_requests\":true,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":[\"ignore-user-1\",\"ignore-user-2\"],\"ignore_requests\":[\"ignore-request-1\"]}," +
                "\"compliance\":{" +
                    "\"enabled\":true,\"external_config\":true,\"internal_config\":true," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":{\"test-read-watch-field-1\":[]},\"read_ignore_users\":[\"test-user-1\"]," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":false," +
                    "\"write_watched_indices\":[\"test-write-watch-index\"],\"write_ignore_users\":[\"test-user-2\"]}}", json);
    }

    @Test
    public void testNullSerialize() throws IOException {
        // arrange

        final AuditConfig.Filter audit = AuditConfig.Filter.from(Collections.emptyMap());
        final ComplianceConfig compliance = new ComplianceConfig(true, true, false, true, null, null, true, false, null, null, Settings.EMPTY);
        final AuditConfig auditConfig = new AuditConfig(true, audit, compliance);

        // act
        final String json = objectMapper.writeValueAsString(auditConfig);
        // assert
        assertEquals("{" +
                "\"enabled\":true," +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":[\"GRANTED_PRIVILEGES\",\"AUTHENTICATED\"]," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":[\"GRANTED_PRIVILEGES\",\"AUTHENTICATED\"]," +
                    "\"resolve_bulk_requests\":false,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":[\"kibanaserver\"],\"ignore_requests\":[]}," +
                "\"compliance\":{" +
                    "\"enabled\":true," +
                    "\"external_config\":true,\"internal_config\":false," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":{},\"read_ignore_users\":[\"kibanaserver\"]," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":false,\"write_watched_indices\":[],\"write_ignore_users\":[\"kibanaserver\"]}" +
                "}", json);
    }

    @Test
    public void testNullDeSerialize() throws IOException {
        // arrange
        final String json = "{" +
                "\"enabled\":true," +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":null," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":null," +
                    "\"resolve_bulk_requests\":true,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":null,\"ignore_requests\":null}," +
                "\"compliance\":{" +
                    "\"enabled\":true," +
                    "\"internal_config\":true,\"external_config\":true," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":null,\"read_ignore_users\":null," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":true,\"write_watched_indices\":null,\"write_ignore_users\":null}" +
                "}";

        // act
        final AuditConfig auditConfig = objectMapper.readValue(json, AuditConfig.class);
        // assert
        final AuditConfig.Filter audit = auditConfig.getFilter();
        final ComplianceConfig configCompliance = auditConfig.getCompliance();
        assertEquals(audit.getDisabledRestCategories(), EnumSet.of(GRANTED_PRIVILEGES, AUTHENTICATED));
        assertEquals(audit.getDisabledTransportCategories(), EnumSet.of(GRANTED_PRIVILEGES, AUTHENTICATED));
        assertEquals(DEFAULT_IGNORED_USER, audit.getIgnoredAuditUsersMatcher());
        assertEquals(WildcardMatcher.NONE, audit.getIgnoredAuditRequestsMatcher());
        assertEquals(DEFAULT_IGNORED_USER, configCompliance.getIgnoredComplianceUsersForReadMatcher());
        assertEquals(DEFAULT_IGNORED_USER, configCompliance.getIgnoredComplianceUsersForWriteMatcher());
        assertTrue(configCompliance.getReadEnabledFields().isEmpty());
        assertEquals(WildcardMatcher.NONE, configCompliance.getWatchedWriteIndicesMatcher());
        assertEquals(".opendistro_security", configCompliance.getOpendistrosecurityIndex());
    }

    @Test
    public void testCustomSettings() throws IOException {
        // arrange
        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, "test-security-index")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT, "internal_elasticsearch")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ES_INDEX,
                        "test-auditlog-index")
                .build();
        final ObjectMapper customObjectMapper = new ObjectMapper();
        InjectableValues.Std iv = new InjectableValues.Std();
        iv.addValue(Settings.class, settings);
        customObjectMapper.setInjectableValues(iv);

        final String json = "{" +
                "\"enabled\":true," +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":null," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":null," +
                    "\"resolve_bulk_requests\":true,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":null,\"ignore_requests\":null}," +
                "\"compliance\":{" +
                "\"enabled\":true," +
                    "\"internal_config\":true,\"external_config\":true," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":null,\"read_ignore_users\":null," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":true,\"write_watched_indices\":null,\"write_ignore_users\":null}" +
                "}";

        // act
        final AuditConfig auditConfig = customObjectMapper.readValue(json, AuditConfig.class);

        // assert
        final AuditConfig.Filter audit = auditConfig.getFilter();
        final ComplianceConfig configCompliance = auditConfig.getCompliance();
        assertEquals(audit.getDisabledRestCategories(), EnumSet.of(GRANTED_PRIVILEGES, AUTHENTICATED));
        assertEquals(audit.getDisabledTransportCategories(), EnumSet.of(GRANTED_PRIVILEGES, AUTHENTICATED));
        assertEquals(DEFAULT_IGNORED_USER, audit.getIgnoredAuditUsersMatcher());
        assertEquals(WildcardMatcher.NONE, audit.getIgnoredAuditRequestsMatcher());
        assertEquals(DEFAULT_IGNORED_USER, configCompliance.getIgnoredComplianceUsersForReadMatcher());
        assertEquals(DEFAULT_IGNORED_USER, configCompliance.getIgnoredComplianceUsersForWriteMatcher());
        assertTrue(configCompliance.getReadEnabledFields().isEmpty());
        assertEquals(WildcardMatcher.NONE, configCompliance.getWatchedWriteIndicesMatcher());
        assertEquals("test-security-index", configCompliance.getOpendistrosecurityIndex());
        assertEquals("test-auditlog-index", configCompliance.getAuditLogIndex());
    }
}
