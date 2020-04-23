package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuditTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testDefaultSerialize() throws JsonProcessingException {
        // arrange
        final Audit audit = new Audit();
        // act
        final String json = objectMapper.writeValueAsString(audit);
        assertEquals("{\"enable_rest\":true," +
                "\"disabled_rest_categories\":[\"GRANTED_PRIVILEGES\",\"AUTHENTICATED\"]," +
                "\"enable_transport\":true," +
                "\"disabled_transport_categories\":[\"GRANTED_PRIVILEGES\",\"AUTHENTICATED\"]," +
                "\"internal_config\":true," +
                "\"external_config\":false," +
                "\"resolve_bulk_requests\":false," +
                "\"log_request_body\":true," +
                "\"resolve_indices\":true," +
                "\"exclude_sensitive_headers\":true," +
                "\"ignore_users\":[\"kibanaserver\"]," +
                "\"ignore_requests\":[]," +
                "\"immutable_indices\":[]," +
                "\"read_metadata_only\":true," +
                "\"read_watched_fields\":[]," +
                "\"read_ignore_users\":[]," +
                "\"write_metadata_only\":true," +
                "\"write_log_diffs\":false," +
                "\"write_watched_indices\":[]," +
                "\"write_ignore_users\":[]," +
                "\"salt\":\"e1ukloTsQlOgPquJ\"}", json);
    }

    @Test
    public void testDefaultDeserialize() throws IOException {
        // act
        final Audit audit = objectMapper.readValue("{}", Audit.class);
        // assert
        assertTrue(audit.isEnableRest());
        assertEquals(audit.getDisabledRestCategories(), EnumSet.of(AuditCategory.AUTHENTICATED, AuditCategory.GRANTED_PRIVILEGES));
        assertTrue(audit.isEnableTransport());
        assertEquals(audit.getDisabledTransportCategories(), EnumSet.of(AuditCategory.AUTHENTICATED, AuditCategory.GRANTED_PRIVILEGES));
        assertFalse(audit.isResolveBulkRequests());
        assertTrue(audit.isLogRequestBody());
        assertTrue(audit.isResolveIndices());
        assertTrue(audit.isExcludeSensitiveHeaders());
        assertFalse(audit.isExternalConfigEnabled());
        assertTrue(audit.isInternalConfigEnabled());
        assertEquals(audit.getIgnoreUsers(), Collections.singleton("kibanaserver"));
        assertTrue(audit.getIgnoreRequests().isEmpty());
        assertTrue(audit.isReadMetadataOnly());
        assertTrue(audit.getReadIgnoreUsers().isEmpty());
        assertTrue(audit.getReadWatchedFields().isEmpty());
        assertTrue(audit.isWriteMetadataOnly());
        assertFalse(audit.isWriteLogDiffs());
        assertTrue(audit.getWriteIgnoreUsers().isEmpty());
        assertTrue(audit.getWriteWatchedIndices().isEmpty());
    }

    @Test
    public void testDeserialize() throws IOException {
        // arrange
        final String json = "{\"enable_rest\":true," +
                "\"disabled_rest_categories\":[\"AUTHENTICATED\"]," +
                "\"enable_transport\":true," +
                "\"disabled_transport_categories\":[\"SSL_EXCEPTION\"]," +
                "\"internal_config\":true," +
                "\"external_config\":true," +
                "\"resolve_bulk_requests\":true," +
                "\"log_request_body\":true," +
                "\"resolve_indices\":true," +
                "\"exclude_sensitive_headers\":true," +
                "\"ignore_users\":[\"test-user-1\"]," +
                "\"ignore_requests\":[\"test-request\"]," +
                "\"immutable_indices\":[\"test-index\"]," +
                "\"read_metadata_only\":true," +
                "\"read_watched_fields\":[\"test-read-watch-field\"]," +
                "\"read_ignore_users\":[\"test-user-2\"]," +
                "\"write_metadata_only\":true," +
                "\"write_log_diffs\":true," +
                "\"write_watched_indices\":[\"test-write-watch-index\"]," +
                "\"write_ignore_users\":[\"test-user-3\"]}";
        // act
        final Audit audit = objectMapper.readValue(json, Audit.class);
        // assert
        assertTrue(audit.isEnableRest());
        assertEquals(audit.getDisabledRestCategories(), EnumSet.of(AuditCategory.AUTHENTICATED));
        assertTrue(audit.isEnableTransport());
        assertEquals(audit.getDisabledTransportCategories(), EnumSet.of(AuditCategory.SSL_EXCEPTION));
        assertTrue(audit.isResolveBulkRequests());
        assertTrue(audit.isLogRequestBody());
        assertTrue(audit.isResolveIndices());
        assertTrue(audit.isExcludeSensitiveHeaders());
        assertTrue(audit.isExternalConfigEnabled());
        assertTrue(audit.isInternalConfigEnabled());
        assertEquals(audit.getIgnoreUsers(), Collections.singleton("test-user-1"));
        assertEquals(audit.getIgnoreRequests(), Collections.singleton("test-request"));
        assertTrue(audit.isReadMetadataOnly());
        assertEquals(audit.getReadIgnoreUsers(), Collections.singleton("test-user-2"));
        assertEquals(audit.getReadWatchedFields(), Collections.singletonList("test-read-watch-field"));
        assertTrue(audit.isWriteMetadataOnly());
        assertTrue(audit.isWriteLogDiffs());
        assertEquals(audit.getWriteIgnoreUsers(), Collections.singleton("test-user-3"));
        assertEquals(audit.getWriteWatchedIndices(), Collections.singletonList("test-write-watch-index"));
    }

    @Test
    public void testSerialize() throws IOException {
        // arrange
        final Audit audit = new Audit();
        audit.setDisabledRestCategories(EnumSet.of(AuditCategory.GRANTED_PRIVILEGES, AuditCategory.FAILED_LOGIN));
        audit.setDisabledTransportCategories(EnumSet.of(AuditCategory.AUTHENTICATED));
        audit.setResolveBulkRequests(true);
        audit.setInternalConfigEnabled(true);
        audit.setExternalConfigEnabled(true);
        audit.setReadIgnoreUsers(Collections.singleton("test-user-1"));
        audit.setWriteIgnoreUsers(Collections.singleton("test-user-2"));
        audit.setReadWatchedFields(Collections.singletonList("test-read-watch-field-1"));
        audit.setWriteWatchedIndices(Collections.singletonList("test-write-watch-index"));
        // act
        final String json = objectMapper.writeValueAsString(audit);
        // assert
        assertEquals("{\"enable_rest\":true," +
                "\"disabled_rest_categories\":[\"FAILED_LOGIN\",\"GRANTED_PRIVILEGES\"]," +
                "\"enable_transport\":true," +
                "\"disabled_transport_categories\":[\"AUTHENTICATED\"]," +
                "\"internal_config\":true," +
                "\"external_config\":true," +
                "\"resolve_bulk_requests\":true," +
                "\"log_request_body\":true," +
                "\"resolve_indices\":true," +
                "\"exclude_sensitive_headers\":true," +
                "\"ignore_users\":[\"kibanaserver\"]," +
                "\"ignore_requests\":[]," +
                "\"immutable_indices\":[]," +
                "\"read_metadata_only\":true," +
                "\"read_watched_fields\":[\"test-read-watch-field-1\"]," +
                "\"read_ignore_users\":[\"test-user-1\"]," +
                "\"write_metadata_only\":true," +
                "\"write_log_diffs\":false," +
                "\"write_watched_indices\":[\"test-write-watch-index\"]," +
                "\"write_ignore_users\":[\"test-user-2\"]," +
                "\"salt\":\"e1ukloTsQlOgPquJ\"}", json);
    }

    @Test
    public void testKeysSet() {
        assertEquals(Audit.Key.KEYS.size(), 21);
        assertEquals(Audit.Key.KEYS, ImmutableSet.of(
                "enable_rest", "disabled_rest_categories",
                "enable_transport", "disabled_transport_categories",
                "internal_config", "external_config",
                "resolve_bulk_requests", "log_request_body", "resolve_indices", "exclude_sensitive_headers",
                "ignore_users", "ignore_requests", "immutable_indices",
                "read_metadata_only", "read_watched_fields", "read_ignore_users",
                "write_metadata_only", "write_log_diffs", "write_watched_indices", "write_ignore_users", "salt"));
    }

    @Test
    public void testNullSerialize() throws IOException {
        // arrange
        final Audit audit = new Audit();
        audit.setDisabledRestCategories(null);
        audit.setDisabledTransportCategories(null);
        audit.setIgnoreUsers(null);
        audit.setIgnoreRequests(null);
        audit.setImmutableIndices(null);
        audit.setReadIgnoreUsers(null);
        audit.setWriteIgnoreUsers(null);
        audit.setReadWatchedFields(null);
        audit.setWriteWatchedIndices(null);
        // act
        final String json = objectMapper.writeValueAsString(audit);
        // assert
        assertEquals("{\"enable_rest\":true," +
                "\"disabled_rest_categories\":[]," +
                "\"enable_transport\":true," +
                "\"disabled_transport_categories\":[]," +
                "\"internal_config\":true," +
                "\"external_config\":false," +
                "\"resolve_bulk_requests\":false," +
                "\"log_request_body\":true," +
                "\"resolve_indices\":true," +
                "\"exclude_sensitive_headers\":true," +
                "\"ignore_users\":[\"kibanaserver\"]," +
                "\"ignore_requests\":[]," +
                "\"immutable_indices\":[]," +
                "\"read_metadata_only\":true," +
                "\"read_watched_fields\":[]," +
                "\"read_ignore_users\":[]," +
                "\"write_metadata_only\":true," +
                "\"write_log_diffs\":false," +
                "\"write_watched_indices\":[]," +
                "\"write_ignore_users\":[]," +
                "\"salt\":\"e1ukloTsQlOgPquJ\"}", json);
    }

    @Test
    public void testNullDeSerialize() throws IOException {
        // arrange
        final String json = "{" +
                "\"disabled_rest_categories\":null," +
                "\"disabled_transport_categories\":null," +
                "\"ignore_users\":null," +
                "\"ignore_requests\":null," +
                "\"immutable_indices\":null," +
                "\"read_watched_fields\":null," +
                "\"read_ignore_users\":null," +
                "\"write_watched_indices\":null," +
                "\"write_ignore_users\":null}";
        // act
        final Audit audit = objectMapper.readValue(json, Audit.class);
        // assert
        assertTrue(audit.getDisabledRestCategories().isEmpty());
        assertTrue(audit.getDisabledTransportCategories().isEmpty());
        assertTrue(audit.getIgnoreUsers().isEmpty());
        assertTrue(audit.getIgnoreRequests().isEmpty());
        assertTrue(audit.getImmutableIndices().isEmpty());
        assertTrue(audit.getReadIgnoreUsers().isEmpty());
        assertTrue(audit.getWriteIgnoreUsers().isEmpty());
        assertTrue(audit.getReadWatchedFields().isEmpty());
        assertTrue(audit.getWriteWatchedIndices().isEmpty());
    }

    @Test
    public void testValidateThrowsException() {
        // assert
        thrown.expect(IllegalArgumentException.class);
        // arrange
        final List<String> list = ImmutableList.of("testing");
        // act
        Audit.Key.validate(list);
    }

    @Test
    public void testValidate() {
        // arrange
        final List<String> list = ImmutableList.of("enable_rest", "log_request_body");
        // act
        Audit.Key.validate(list);
    }
}
