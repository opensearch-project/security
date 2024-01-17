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

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ComplianceConfigTest {

    @Test
    public void testDefault() {
        // arrange
        final WildcardMatcher defaultIgnoredUserMatcher = WildcardMatcher.from("kibanaserver");
        // act
        final ComplianceConfig complianceConfig = ComplianceConfig.from(Settings.EMPTY);
        // assert
        assertTrue(complianceConfig.isEnabled());
        assertFalse(complianceConfig.shouldLogExternalConfig());
        assertFalse(complianceConfig.shouldLogInternalConfig());
        assertFalse(complianceConfig.shouldLogReadMetadataOnly());
        assertFalse(complianceConfig.shouldLogWriteMetadataOnly());
        assertFalse(complianceConfig.shouldLogDiffsForWrite());
        assertEquals(defaultIgnoredUserMatcher, complianceConfig.getIgnoredComplianceUsersForReadMatcher());
        assertEquals(defaultIgnoredUserMatcher, complianceConfig.getIgnoredComplianceUsersForWriteMatcher());
    }

    @Test
    public void testConfig() {
        // arrange
        final String testSalt = "abcdefghijklmnop";
        final Settings settings = Settings.builder()
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
            .put(ConfigConstants.SECURITY_COMPLIANCE_SALT, testSalt)
            .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "write_index1", "write_index_pattern*")
            .putList(
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                "read_index1,field1,field2",
                "read_index_pattern*,field1,field_pattern*"
            )
            .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, "test-user-1", "test-user-2")
            .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, "test-user-3", "test-user-4")
            .build();

        // act
        final ComplianceConfig complianceConfig = ComplianceConfig.from(settings);

        // assert
        assertTrue(complianceConfig.isEnabled());
        assertTrue(complianceConfig.shouldLogExternalConfig());
        assertTrue(complianceConfig.shouldLogInternalConfig());
        assertTrue(complianceConfig.shouldLogReadMetadataOnly());
        assertTrue(complianceConfig.shouldLogWriteMetadataOnly());
        assertFalse(complianceConfig.shouldLogDiffsForWrite());
        assertEquals(
            WildcardMatcher.from(ImmutableSet.of("test-user-1", "test-user-2")),
            complianceConfig.getIgnoredComplianceUsersForReadMatcher()
        );
        assertEquals(
            WildcardMatcher.from(ImmutableSet.of("test-user-3", "test-user-4")),
            complianceConfig.getIgnoredComplianceUsersForWriteMatcher()
        );

        // test write history
        assertTrue(complianceConfig.writeHistoryEnabledForIndex(".opendistro_security"));
        assertTrue(complianceConfig.writeHistoryEnabledForIndex("write_index1"));
        assertFalse(complianceConfig.writeHistoryEnabledForIndex("write_index2"));
        assertTrue(complianceConfig.writeHistoryEnabledForIndex("write_index_pattern_1"));
        assertTrue(complianceConfig.writeHistoryEnabledForIndex("write_index_pattern_2"));

        // test read history
        assertTrue(complianceConfig.readHistoryEnabledForIndex(".opendistro_security"));
        assertTrue(complianceConfig.readHistoryEnabledForIndex("read_index1"));
        assertFalse(complianceConfig.readHistoryEnabledForIndex("read_index2"));
        assertTrue(complianceConfig.readHistoryEnabledForIndex("read_index_pattern_1"));
        assertTrue(complianceConfig.readHistoryEnabledForIndex("read_index_pattern_2"));

        // test read history field
        assertTrue(complianceConfig.readHistoryEnabledForField("read_index1", "field1"));
        assertTrue(complianceConfig.readHistoryEnabledForField("read_index1", "field2"));
        assertFalse(complianceConfig.readHistoryEnabledForField("read_index1", "field3"));
        assertTrue(complianceConfig.readHistoryEnabledForField("read_index_pattern_1", "field1"));
        assertTrue(complianceConfig.readHistoryEnabledForField("read_index_pattern_2", "field1"));
        assertFalse(complianceConfig.readHistoryEnabledForField("read_index_pattern_2", "field2"));
        assertTrue(complianceConfig.readHistoryEnabledForField("read_index_pattern_2", "field_pattern_1"));
    }

    @Test
    public void testNone() {
        // arrange
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, "NONE")
            .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, "NONE")
            .build();
        // act
        final ComplianceConfig complianceConfig = ComplianceConfig.from(settings);
        // assert
        assertSame(WildcardMatcher.NONE, complianceConfig.getIgnoredComplianceUsersForReadMatcher());
        assertSame(WildcardMatcher.NONE, complianceConfig.getIgnoredComplianceUsersForWriteMatcher());
    }

    @Test
    public void testEmpty() {
        // arrange
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, Collections.emptyList())
            .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, Collections.emptyList())
            .build();
        // act
        final ComplianceConfig complianceConfig = ComplianceConfig.from(settings);
        // assert
        assertSame(WildcardMatcher.NONE, complianceConfig.getIgnoredComplianceUsersForReadMatcher());
        assertSame(WildcardMatcher.NONE, complianceConfig.getIgnoredComplianceUsersForWriteMatcher());
    }

    @Test
    public void testLogState() {
        // arrange
        final var logger = Mockito.mock(Logger.class);
        final ComplianceConfig complianceConfig = ComplianceConfig.from(Settings.EMPTY);
        // act
        complianceConfig.log(logger);
        // assert: don't validate content, but ensure message's logged is generally consistant
        verify(logger, times(6)).info(anyString(), anyString());
        verify(logger, times(1)).info(anyString(), isNull(String.class));
        verify(logger, times(1)).info(anyString(), any(Map.class));
        verify(logger, times(3)).info(anyString(), any(WildcardMatcher.class));
        verifyNoMoreInteractions(logger);
    }

    @Test
    public void testReadWriteHistoryEnabledForIndex_rollingIndex() {
        // arrange
        final var date = new AtomicReference<DateTime>();
        final Consumer<Integer> setYear = (year) -> { date.set(new DateTime(year, 1, 1, 1, 2, DateTimeZone.UTC)); };
        final ComplianceConfig complianceConfig = ComplianceConfig.from(
            Settings.builder()
                .put(
                    ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX,
                    "'audit-log-index'-YYYY-MM-dd"
                )
                .put(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, "internal_opensearch")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, "*")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "*")
                .build(),
            date::get
        );

        // act: Don't log for null indices
        assertThat(complianceConfig.readHistoryEnabledForIndex(null), equalTo(false));
        assertThat(complianceConfig.writeHistoryEnabledForIndex(null), equalTo(false));
        // act: Don't log for the security indices
        assertThat(complianceConfig.readHistoryEnabledForIndex(complianceConfig.getSecurityIndex()), equalTo(false));
        assertThat(complianceConfig.writeHistoryEnabledForIndex(complianceConfig.getSecurityIndex()), equalTo(false));

        // act: Don't log for the current audit log
        setYear.accept(1337);
        assertThat(complianceConfig.readHistoryEnabledForIndex("audit-log-index-1337-01-01"), equalTo(false));
        assertThat(complianceConfig.writeHistoryEnabledForIndex("audit-log-index-1337-01-01"), equalTo(false));

        // act: Log for current audit log when it does not match the date
        setYear.accept(2048);
        // See https://github.com/opensearch-project/security/issues/3950
        // assertThat(complianceConfig.readHistoryEnabledForIndex("audit-log-index-1337-01-01"), equalTo(true));
        assertThat(complianceConfig.writeHistoryEnabledForIndex("audit-log-index-1337-01-01"), equalTo(true));

        // act: Log for any matching index
        assertThat(complianceConfig.readHistoryEnabledForIndex("my-data"), equalTo(true));
        assertThat(complianceConfig.writeHistoryEnabledForIndex("my-data"), equalTo(true));
    }

    @Test
    public void testReadWriteHistoryEnabledForIndex_staticIndex() {
        // arrange
        final ComplianceConfig complianceConfig = ComplianceConfig.from(
            Settings.builder()
                .put(
                    ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX,
                    "audit-log-index"
                )
                .put(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, "internal_opensearch")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, "*")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "*")
                .build()
        );

        // act: Don't log for the static audit log
        assertThat(complianceConfig.readHistoryEnabledForIndex(complianceConfig.getAuditLogIndex()), equalTo(false));
        assertThat(complianceConfig.writeHistoryEnabledForIndex(complianceConfig.getAuditLogIndex()), equalTo(false));

        // act: Log for any matching index
        assertThat(complianceConfig.readHistoryEnabledForIndex("my-data"), equalTo(true));
        assertThat(complianceConfig.writeHistoryEnabledForIndex("my-data"), equalTo(true));
    }
}
