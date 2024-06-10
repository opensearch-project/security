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

package org.opensearch.security.auditlog.config;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import static org.opensearch.security.auditlog.impl.AuditCategory.AUTHENTICATED;
import static org.opensearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class AuditConfigSerializeTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final WildcardMatcher DEFAULT_IGNORED_USER = WildcardMatcher.from(AuditConfig.DEFAULT_IGNORED_USERS);

    @Before
    public void setUp() {
        InjectableValues.Std iv = new InjectableValues.Std();
        iv.addValue(Settings.class, Settings.EMPTY);
        objectMapper.setInjectableValues(iv);
    }

    @Test
    public void testDefaultSerialize() throws IOException {
        // arrange
        final AuditConfig audit = new AuditConfig(true, null, null);
        // act
        final String json = objectMapper.writeValueAsString(audit);

        final XContentBuilder jsonBuilder = XContentFactory.jsonBuilder()
            .startObject()
            .field("enabled", true)
            .startObject("audit")
            .field("enable_rest", true)
            .field("disabled_rest_categories", ImmutableList.of("AUTHENTICATED", "GRANTED_PRIVILEGES"))
            .field("enable_transport", true)
            .field("disabled_transport_categories", ImmutableList.of("AUTHENTICATED", "GRANTED_PRIVILEGES"))
            .field("resolve_bulk_requests", false)
            .field("log_request_body", true)
            .field("resolve_indices", true)
            .field("exclude_sensitive_headers", true)
            .field("ignore_users", Collections.singletonList("kibanaserver"))
            .field("ignore_requests", Collections.emptyList())
            .field("ignore_headers", Collections.emptyList())
            .field("ignore_url_params", Collections.emptyList())
            .endObject()
            .startObject("compliance")
            .field("enabled", true)
            .field("external_config", false)
            .field("internal_config", false)
            .field("read_metadata_only", false)
            .field("read_watched_fields", Collections.emptyMap())
            .field("read_ignore_users", Collections.singletonList("kibanaserver"))
            .field("write_metadata_only", false)
            .field("write_log_diffs", false)
            .field("write_watched_indices", Collections.emptyList())
            .field("write_ignore_users", Collections.singletonList("kibanaserver"))
            .endObject()
            .endObject();

        assertTrue(compareJson(jsonBuilder.toString(), json));
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
        assertEquals(WildcardMatcher.NONE, audit.getIgnoredCustomHeadersMatcher());
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
        final XContentBuilder jsonBuilder = XContentFactory.jsonBuilder()
            .startObject()
            .field("enabled", true)
            .startObject("audit")
            .field("enable_rest", true)
            .field("disabled_rest_categories", Collections.singletonList("AUTHENTICATED"))
            .field("enable_transport", true)
            .field("disabled_transport_categories", Collections.singletonList("SSL_EXCEPTION"))
            .field("resolve_bulk_requests", true)
            .field("log_request_body", true)
            .field("resolve_indices", true)
            .field("exclude_sensitive_headers", true)
            .field("ignore_users", Collections.singletonList("test-user-1"))
            .field("ignore_requests", Collections.singletonList("test-request"))
            .field("ignore_headers", Collections.singletonList("test-headers"))
            .field("ignore_url_params", Collections.singletonList("test-param"))
            .endObject()
            .startObject("compliance")
            .field("enabled", true)
            .field("external_config", true)
            .field("internal_config", true)
            .field("read_metadata_only", true)
            .field("read_watched_fields", Collections.singletonMap("test-read-watch-field", Collections.singleton("test-field-1")))
            .field("read_ignore_users", Collections.singletonList("test-user-2"))
            .field("write_metadata_only", true)
            .field("write_log_diffs", false)
            .field("write_watched_indices", Collections.singletonList("test-write-watch-index"))
            .field("write_ignore_users", Collections.singletonList("test-user-3"))
            .endObject()
            .endObject();
        final String json = jsonBuilder.toString();

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
        assertEquals(
            WildcardMatcher.from(Collections.singleton("test-user-2")),
            configCompliance.getIgnoredComplianceUsersForReadMatcher()
        );
        assertEquals(
            Collections.singletonMap(WildcardMatcher.from("test-read-watch-field"), Collections.singleton("test-field-1")),
            configCompliance.getReadEnabledFields()
        );
        assertTrue(configCompliance.shouldLogWriteMetadataOnly());
        assertFalse(configCompliance.shouldLogDiffsForWrite());
        assertEquals(
            WildcardMatcher.from(Collections.singleton("test-user-3")),
            configCompliance.getIgnoredComplianceUsersForWriteMatcher()
        );
        assertEquals(WildcardMatcher.from("test-write-watch-index"), configCompliance.getWatchedWriteIndicesMatcher());
    }

    @Test
    public void testSerialize() throws IOException {
        // arrange
        final AuditConfig.Filter audit = new AuditConfig.Filter(
            true,
            true,
            true,
            true,
            true,
            true,
            ImmutableSet.of("ignore-user-1", "ignore-user-2"),
            ImmutableSet.of("ignore-request-1"),
            ImmutableSet.of("test-header"),
            ImmutableSet.of("test-param"),
            EnumSet.of(AuditCategory.FAILED_LOGIN, AuditCategory.GRANTED_PRIVILEGES),
            EnumSet.of(AUTHENTICATED)
        );
        final ComplianceConfig compliance = new ComplianceConfig(
            true,
            true,
            true,
            true,
            Collections.singletonMap("test-read-watch-field-1", Collections.emptyList()),
            Collections.singleton("test-user-1"),
            true,
            false,
            Collections.singletonList("test-write-watch-index"),
            Collections.singleton("test-user-2"),
            null,
            Settings.EMPTY
        );
        final AuditConfig auditConfig = new AuditConfig(true, audit, compliance);
        final XContentBuilder jsonBuilder = XContentFactory.jsonBuilder()
            .startObject()
            .field("enabled", true)
            .startObject("audit")
            .field("enable_rest", true)
            .field("disabled_rest_categories", ImmutableList.of("FAILED_LOGIN", "GRANTED_PRIVILEGES"))
            .field("enable_transport", true)
            .field("disabled_transport_categories", Collections.singletonList("AUTHENTICATED"))
            .field("resolve_bulk_requests", true)
            .field("log_request_body", true)
            .field("resolve_indices", true)
            .field("exclude_sensitive_headers", true)
            .field("ignore_users", ImmutableList.of("ignore-user-1", "ignore-user-2"))
            .field("ignore_requests", Collections.singletonList("ignore-request-1"))
            .field("ignore_headers", Collections.singletonList("test-header"))
            .field("ignore_url_params", Collections.singletonList("test-param"))
            .endObject()
            .startObject("compliance")
            .field("enabled", true)
            .field("external_config", true)
            .field("internal_config", true)
            .field("read_metadata_only", true)
            .field("read_watched_fields", Collections.singletonMap("test-read-watch-field-1", Collections.emptyList()))
            .field("read_ignore_users", Collections.singletonList("test-user-1"))
            .field("write_metadata_only", true)
            .field("write_log_diffs", false)
            .field("write_watched_indices", Collections.singletonList("test-write-watch-index"))
            .field("write_ignore_users", Collections.singletonList("test-user-2"))
            .endObject()
            .endObject();

        // act
        final String json = objectMapper.writeValueAsString(auditConfig);
        // assert
        assertTrue(compareJson(jsonBuilder.toString(), json));
    }

    @Test
    public void testNullSerialize() throws IOException {
        // arrange

        final AuditConfig.Filter audit = AuditConfig.Filter.from(Collections.emptyMap());
        final ComplianceConfig compliance = ComplianceConfig.from(Collections.emptyMap(), Settings.EMPTY);
        final AuditConfig auditConfig = new AuditConfig(true, audit, compliance);
        final XContentBuilder jsonBuilder = XContentFactory.jsonBuilder()
            .startObject()
            .field("enabled", true)
            .startObject("audit")
            .field("enable_rest", true)
            .field("disabled_rest_categories", ImmutableList.of("AUTHENTICATED", "GRANTED_PRIVILEGES"))
            .field("enable_transport", true)
            .field("disabled_transport_categories", ImmutableList.of("AUTHENTICATED", "GRANTED_PRIVILEGES"))
            .field("resolve_bulk_requests", false)
            .field("log_request_body", true)
            .field("resolve_indices", true)
            .field("exclude_sensitive_headers", true)
            .field("ignore_users", ImmutableList.of("kibanaserver"))
            .field("ignore_requests", Collections.emptyList())
            .field("ignore_headers", Collections.emptyList())
            .field("ignore_url_params", Collections.emptyList())
            .endObject()
            .startObject("compliance")
            .field("enabled", true)
            .field("external_config", false)
            .field("internal_config", false)
            .field("read_metadata_only", false)
            .field("read_watched_fields", Collections.emptyMap())
            .field("read_ignore_users", Collections.singletonList("kibanaserver"))
            .field("write_metadata_only", false)
            .field("write_log_diffs", false)
            .field("write_watched_indices", Collections.emptyList())
            .field("write_ignore_users", Collections.singletonList("kibanaserver"))
            .endObject()
            .endObject();

        // act
        final String json = objectMapper.writeValueAsString(auditConfig);
        // assert

        assertTrue(compareJson(jsonBuilder.toString(), json));
    }

    @Test
    public void testNullDeSerialize() throws IOException {
        // arrange
        final String json = "{" + "\"audit\":{}," + "\"compliance\":{}" + "}";

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
        assertEquals(".opendistro_security", configCompliance.getSecurityIndex());
    }

    @Test
    public void testCustomSettings() throws IOException {
        // arrange
        final Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, "test-security-index")
            .put(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, "internal_opensearch")
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX,
                "test-auditlog-index"
            )
            .build();
        final ObjectMapper customObjectMapper = new ObjectMapper();
        InjectableValues.Std iv = new InjectableValues.Std();
        iv.addValue(Settings.class, settings);
        customObjectMapper.setInjectableValues(iv);

        final XContentBuilder jsonBuilder = XContentFactory.jsonBuilder()
            .startObject()
            .field("enabled", true)
            .startObject("audit")
            .field("enable_rest", true)
            .field("enable_transport", true)
            .field("resolve_bulk_requests", true)
            .field("log_request_body", true)
            .field("resolve_indices", true)
            .field("exclude_sensitive_headers", true)
            .endObject()
            .startObject("compliance")
            .field("enabled", true)
            .field("external_config", true)
            .field("internal_config", true)
            .field("read_metadata_only", true)
            .field("write_metadata_only", true)
            .field("write_log_diffs", false)
            .endObject()
            .endObject();
        final String json = jsonBuilder.toString();

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
        assertEquals("test-security-index", configCompliance.getSecurityIndex());
        assertEquals("test-auditlog-index", configCompliance.getAuditLogIndex());
    }

    private boolean compareJson(final String json1, final String json2) throws JsonProcessingException {
        ObjectNode objectNode1 = objectMapper.readValue(json1, ObjectNode.class);
        ObjectNode objectNode2 = objectMapper.readValue(json2, ObjectNode.class);
        return objectNode1.equals(objectNode2);
    }
}
