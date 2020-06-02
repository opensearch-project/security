package com.amazon.opendistroforelasticsearch.security.auditlog.compliance;

import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;

import com.google.common.collect.ImmutableSet;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;

public class ComplianceConfigTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testDefault() {
        // act
        final ComplianceConfig complianceConfig = ComplianceConfig.from(Settings.EMPTY);
        // assert
        assertTrue(complianceConfig.isEnabled());
        assertFalse(complianceConfig.shouldLogExternalConfig());
        assertFalse(complianceConfig.shouldLogInternalConfig());
        assertFalse(complianceConfig.shouldLogReadMetadataOnly());
        assertFalse(complianceConfig.shouldLogWriteMetadataOnly());
        assertFalse(complianceConfig.shouldLogDiffsForWrite());
        assertEquals(16, complianceConfig.getSalt16().length);
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
        assertArrayEquals(testSalt.getBytes(StandardCharsets.UTF_8), complianceConfig.getSalt16());
        assertEquals(16, complianceConfig.getSalt16().length);

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
    public void testSaltThrowsExceptionWhenInsufficientBytesProvided() {
        // assert
        thrown.expect(ElasticsearchException.class);
        thrown.expectMessage("Provided compliance salt abcd must at least contain 16 bytes");

        // arrange
        final String testSalt = "abcd";
        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, testSalt)
                .build();
        // act
        ComplianceConfig.from(settings);
    }

    @Test
    public void testSaltUsesOnlyFirst16Bytes() {
        // arrange
        final String testSalt = "abcdefghijklmnopqrstuvwxyz";
        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, testSalt)
                .build();
        // act
        final ComplianceConfig complianceConfig = ComplianceConfig.from(settings);

        // assert
        assertEquals(16, complianceConfig.getSalt16().length);
        assertArrayEquals(testSalt.substring(0, 16).getBytes(StandardCharsets.UTF_8), complianceConfig.getSalt16());
    }
}
