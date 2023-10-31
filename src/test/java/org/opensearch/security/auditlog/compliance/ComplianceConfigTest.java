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

import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

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

        assertThat(complianceConfig.getIgnoredComplianceUsersForReadMatcher(), is(defaultIgnoredUserMatcher));
        assertThat(complianceConfig.getIgnoredComplianceUsersForWriteMatcher(), is(defaultIgnoredUserMatcher));

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
        assertThat(
            complianceConfig.getIgnoredComplianceUsersForReadMatcher(),
            is(WildcardMatcher.from(ImmutableSet.of("test-user-1", "test-user-2")))
        );
        assertThat(
            complianceConfig.getIgnoredComplianceUsersForWriteMatcher(),
            is(WildcardMatcher.from(ImmutableSet.of("test-user-3", "test-user-4")))
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
}
