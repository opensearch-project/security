package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

public class AuditTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testDefaultSerialize() throws JsonProcessingException {
        // arrange
        final AuditConfig audit = new AuditConfig();
        // act
        final String json = objectMapper.writeValueAsString(audit);
        assertEquals("{" +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":[\"GRANTED_PRIVILEGES\",\"AUTHENTICATED\"]," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":[\"GRANTED_PRIVILEGES\",\"AUTHENTICATED\"]," +
                    "\"resolve_bulk_requests\":false,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":[\"kibanaserver\"],\"ignore_requests\":[]}," +
                "\"compliance\":{" +
                    "\"internal_config\":true,\"external_config\":false," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":[],\"read_ignore_users\":[]," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":false,\"write_watched_indices\":[],\"write_ignore_users\":[]}" +
                "}", json);
    }

    @Test
    public void testDefaultDeserialize() throws IOException {
        // act
        final AuditConfig auditConfig = objectMapper.readValue("{}", AuditConfig.class);
        final AuditConfig.Filter audit = auditConfig.getFilter();
        final AuditConfig.Compliance compliance = auditConfig.getCompliance();
        // assert
        assertTrue(audit.isRestApiAuditEnabled());
        assertEquals(audit.getDisabledRestCategories(), EnumSet.of(AuditCategory.AUTHENTICATED, AuditCategory.GRANTED_PRIVILEGES));
        assertTrue(audit.isTransportApiAuditEnabled());
        assertEquals(audit.getDisabledTransportCategories(), EnumSet.of(AuditCategory.AUTHENTICATED, AuditCategory.GRANTED_PRIVILEGES));
        assertFalse(audit.shouldResolveBulkRequests());
        assertTrue(audit.shouldLogRequestBody());
        assertTrue(audit.shouldResolveIndices());
        assertTrue(audit.shouldExcludeSensitiveHeaders());
        assertFalse(compliance.isExternalConfigEnabled());
        assertTrue(compliance.isInternalConfigEnabled());
        assertEquals(audit.getIgnoredAuditUsers(), Collections.singleton("kibanaserver"));
        assertTrue(audit.getIgnoredAuditRequests().isEmpty());
        assertTrue(compliance.isReadMetadataOnly());
        assertTrue(compliance.getReadIgnoreUsers().isEmpty());
        assertTrue(compliance.getReadWatchedFields().isEmpty());
        assertTrue(compliance.isWriteMetadataOnly());
        assertFalse(compliance.isWriteLogDiffs());
        assertTrue(compliance.getWriteIgnoreUsers().isEmpty());
        assertTrue(compliance.getWriteWatchedIndices().isEmpty());
    }

    @Test
    public void testDeserialize() throws IOException {
        // arrange
        final String json = "{" +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":[\"AUTHENTICATED\"]," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":[\"SSL_EXCEPTION\"]," +
                    "\"resolve_bulk_requests\":true,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":[\"test-user-1\"],\"ignore_requests\":[\"test-request\"]}," +
                "\"compliance\":{" +
                    "\"internal_config\":true,\"external_config\":true," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":[\"test-read-watch-field\"],\"read_ignore_users\":[\"test-user-2\"]," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":true,\"write_watched_indices\":[\"test-write-watch-index\"],\"write_ignore_users\":[\"test-user-3\"]}" +
                "}";

        // act
        final AuditConfig auditConfig = objectMapper.readValue(json, AuditConfig.class);
        final AuditConfig.Filter audit = auditConfig.getFilter();
        final AuditConfig.Compliance configCompliance = auditConfig.getCompliance();
        // assert
        assertTrue(audit.isRestApiAuditEnabled());
        assertEquals(audit.getDisabledRestCategories(), EnumSet.of(AuditCategory.AUTHENTICATED));
        assertTrue(audit.isTransportApiAuditEnabled());
        assertEquals(audit.getDisabledTransportCategories(), EnumSet.of(AuditCategory.SSL_EXCEPTION));
        assertTrue(audit.shouldResolveBulkRequests());
        assertTrue(audit.shouldLogRequestBody());
        assertTrue(audit.shouldResolveIndices());
        assertTrue(audit.shouldExcludeSensitiveHeaders());
        assertTrue(configCompliance.isExternalConfigEnabled());
        assertTrue(configCompliance.isInternalConfigEnabled());
        assertEquals(audit.getIgnoredAuditUsers(), Collections.singleton("test-user-1"));
        assertEquals(audit.getIgnoredAuditRequests(), Collections.singleton("test-request"));
        assertTrue(configCompliance.isReadMetadataOnly());
        assertEquals(configCompliance.getReadIgnoreUsers(), Collections.singleton("test-user-2"));
        assertEquals(configCompliance.getReadWatchedFields(), Collections.singletonList("test-read-watch-field"));
        assertTrue(configCompliance.isWriteMetadataOnly());
        assertTrue(configCompliance.isWriteLogDiffs());
        assertEquals(configCompliance.getWriteIgnoreUsers(), Collections.singleton("test-user-3"));
        assertEquals(configCompliance.getWriteWatchedIndices(), Collections.singletonList("test-write-watch-index"));
    }

    @Test
    public void testSerialize() throws IOException {
        // arrange
        final AuditConfig auditConfig = new AuditConfig();
        final AuditConfig.Filter audit = new AuditConfig.Filter();
        final AuditConfig.Compliance compliance = new AuditConfig.Compliance();

        audit.setDisabledRestCategories(EnumSet.of(AuditCategory.GRANTED_PRIVILEGES, AuditCategory.FAILED_LOGIN));
        audit.setDisabledTransportCategories(EnumSet.of(AuditCategory.AUTHENTICATED));
        audit.setResolveBulkRequests(true);
        compliance.setInternalConfigEnabled(true);
        compliance.setExternalConfigEnabled(true);
        compliance.setReadIgnoreUsers(Collections.singleton("test-user-1"));
        compliance.setWriteIgnoreUsers(Collections.singleton("test-user-2"));
        compliance.setReadWatchedFields(Collections.singletonList("test-read-watch-field-1"));
        compliance.setWriteWatchedIndices(Collections.singletonList("test-write-watch-index"));
        auditConfig.setFilter(audit);
        auditConfig.setCompliance(compliance);
        // act
        final String json = objectMapper.writeValueAsString(auditConfig);
        // assert
        assertEquals("{" +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":[\"FAILED_LOGIN\",\"GRANTED_PRIVILEGES\"]," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":[\"AUTHENTICATED\"]," +
                    "\"resolve_bulk_requests\":true,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":[\"kibanaserver\"],\"ignore_requests\":[]}," +
                "\"compliance\":{" +
                    "\"internal_config\":true,\"external_config\":true," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":[\"test-read-watch-field-1\"],\"read_ignore_users\":[\"test-user-1\"]," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":false," +
                    "\"write_watched_indices\":[\"test-write-watch-index\"],\"write_ignore_users\":[\"test-user-2\"]}" +
                "}", json);
    }

    @Test
    public void testNullSerialize() throws IOException {
        // arrange
        final AuditConfig auditConfig = new AuditConfig();
        final AuditConfig.Filter audit = new AuditConfig.Filter();
        final AuditConfig.Compliance compliance = new AuditConfig.Compliance();
        audit.setDisabledRestCategories(null);
        audit.setDisabledTransportCategories(null);
        audit.setIgnoreUsers(null);
        audit.setIgnoreRequests(null);
        compliance.setReadIgnoreUsers(null);
        compliance.setWriteIgnoreUsers(null);
        compliance.setReadWatchedFields(null);
        compliance.setWriteWatchedIndices(null);
        auditConfig.setFilter(audit);
        auditConfig.setCompliance(compliance);

        // act
        final String json = objectMapper.writeValueAsString(auditConfig);
        // assert
        assertEquals("{" +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":[]," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":[]," +
                    "\"resolve_bulk_requests\":false,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":[],\"ignore_requests\":[]}," +
                "\"compliance\":{" +
                    "\"internal_config\":true,\"external_config\":false," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":[],\"read_ignore_users\":[]," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":false,\"write_watched_indices\":[],\"write_ignore_users\":[]}" +
                "}", json);
    }

    @Test
    public void testNullDeSerialize() throws IOException {
        // arrange
        final String json = "{" +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":null," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":null," +
                    "\"resolve_bulk_requests\":true,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":null,\"ignore_requests\":null}," +
                "\"compliance\":{" +
                    "\"internal_config\":true,\"external_config\":true," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":null,\"read_ignore_users\":null," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":true,\"write_watched_indices\":null,\"write_ignore_users\":null}" +
                "}";

        // act
        final AuditConfig auditConfig = objectMapper.readValue(json, AuditConfig.class);
        // assert
        final AuditConfig.Filter audit = auditConfig.getFilter();
        final AuditConfig.Compliance configCompliance = auditConfig.getCompliance();
        assertTrue(audit.getDisabledRestCategories().isEmpty());
        assertTrue(audit.getDisabledTransportCategories().isEmpty());
        assertTrue(audit.getIgnoredAuditRequests().isEmpty());
        assertTrue(audit.getIgnoredAuditUsers().isEmpty());
        assertTrue(configCompliance.getReadIgnoreUsers().isEmpty());
        assertTrue(configCompliance.getWriteIgnoreUsers().isEmpty());
        assertTrue(configCompliance.getReadWatchedFields().isEmpty());
        assertTrue(configCompliance.getWriteWatchedIndices().isEmpty());
    }
}
