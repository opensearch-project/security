/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auditlog.compliance;

import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;

import com.google.common.collect.ImmutableSet;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

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
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, testSalt)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "write_index1", "write_index_pattern*")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, "read_index1,field1,field2", "read_index_pattern*,field1,field_pattern*")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                        "test-user-1", "test-user-2")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                        "test-user-3", "test-user-4")
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
        assertEquals(WildcardMatcher.from(ImmutableSet.of("test-user-1", "test-user-2")), complianceConfig.getIgnoredComplianceUsersForReadMatcher());
        assertEquals(WildcardMatcher.from(ImmutableSet.of("test-user-3", "test-user-4")), complianceConfig.getIgnoredComplianceUsersForWriteMatcher());

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
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                        "NONE")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                        "NONE")
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
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                        Collections.emptyList())
                .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                        Collections.emptyList())
                .build();
        // act
        final ComplianceConfig complianceConfig = ComplianceConfig.from(settings);
        // assert
        assertSame(WildcardMatcher.NONE, complianceConfig.getIgnoredComplianceUsersForReadMatcher());
        assertSame(WildcardMatcher.NONE, complianceConfig.getIgnoredComplianceUsersForWriteMatcher());
    }
}
