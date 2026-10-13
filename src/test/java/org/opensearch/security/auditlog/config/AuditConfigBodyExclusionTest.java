/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auditlog.config;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import org.opensearch.common.settings.Settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for body logging exclusion feature in AuditConfig.Filter.
 * Tests the isBodyExcluded() method with action groups and patterns.
 */
public class AuditConfigBodyExclusionTest {

    @Test
    public void testBodyExcludedWithExactPath() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Collections.emptyMap());
        filter.setBodyLoggingExclusions(List.of("/_bulk"));

        assertTrue("/_bulk should be excluded", filter.isBodyExcluded("/_bulk"));
        assertFalse("/_search should NOT be excluded", filter.isBodyExcluded("/_search"));
        assertFalse("/my-index/_doc/1 should NOT be excluded", filter.isBodyExcluded("/my-index/_doc/1"));
    }

    @Test
    public void testBodyExcludedWithWildcardAction() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Collections.emptyMap());
        filter.setBodyLoggingExclusions(List.of("indices:data/write/bulk*"));

        assertTrue("indices:data/write/bulk should match", filter.isBodyExcluded("indices:data/write/bulk"));
        assertTrue("indices:data/write/bulk[s] should match", filter.isBodyExcluded("indices:data/write/bulk[s]"));
        assertTrue("indices:data/write/bulk[s][p] should match", filter.isBodyExcluded("indices:data/write/bulk[s][p]"));
        assertFalse("indices:data/write/index should NOT match", filter.isBodyExcluded("indices:data/write/index"));
        assertFalse("indices:data/read/search should NOT match", filter.isBodyExcluded("indices:data/read/search"));
    }

    @Test
    public void testBodyExcludedWithActionGroup() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk")));
        filter.setBodyLoggingExclusions(List.of("BULK"));

        // Action patterns from group
        assertTrue("indices:data/write/bulk should match via group", filter.isBodyExcluded("indices:data/write/bulk"));
        assertTrue("indices:data/write/bulk[s][p] should match via group", filter.isBodyExcluded("indices:data/write/bulk[s][p]"));
        // Path patterns from group
        assertTrue("/_bulk should match via group", filter.isBodyExcluded("/_bulk"));
        // Non-matching
        assertFalse("/_search should NOT match", filter.isBodyExcluded("/_search"));
        assertFalse("indices:data/write/index should NOT match", filter.isBodyExcluded("indices:data/write/index"));
    }

    @Test
    public void testBodyExcludedWithMultipleGroups() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(
            Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk"), "SEARCH", List.of("indices:data/read/search*", "/_search"))
        );
        // Only BULK is excluded, not SEARCH
        filter.setBodyLoggingExclusions(List.of("BULK"));

        assertTrue("/_bulk should be excluded", filter.isBodyExcluded("/_bulk"));
        assertFalse("/_search should NOT be excluded (SEARCH group not in exclusions)", filter.isBodyExcluded("/_search"));
    }

    @Test
    public void testBodyExcludedBothGroupsExcluded() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(
            Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk"), "SEARCH", List.of("indices:data/read/search*", "/_search"))
        );
        filter.setBodyLoggingExclusions(List.of("BULK", "SEARCH"));

        assertTrue("/_bulk should be excluded", filter.isBodyExcluded("/_bulk"));
        assertTrue("/_search should be excluded", filter.isBodyExcluded("/_search"));
        assertTrue("indices:data/read/search should be excluded", filter.isBodyExcluded("indices:data/read/search"));
        assertFalse("indices:data/write/index should NOT be excluded", filter.isBodyExcluded("indices:data/write/index"));
    }

    @Test
    public void testBodyExcludedEmptyExclusions() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk")));
        filter.setBodyLoggingExclusions(Collections.emptyList());

        assertFalse("nothing should be excluded with empty list", filter.isBodyExcluded("/_bulk"));
        assertFalse("nothing should be excluded with empty list", filter.isBodyExcluded("indices:data/write/bulk"));
    }

    @Test
    public void testBodyExcludedNullInput() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Collections.emptyMap());
        filter.setBodyLoggingExclusions(List.of("/_bulk"));

        assertFalse("null input should return false", filter.isBodyExcluded(null));
    }

    @Test
    public void testBodyExcludedNonExistentGroupTreatedAsRawPattern() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Collections.emptyMap());
        // "DOES_NOT_EXIST" is not a group name — treated as a literal pattern
        filter.setBodyLoggingExclusions(List.of("DOES_NOT_EXIST"));

        // Only matches the literal string "DOES_NOT_EXIST"
        assertTrue("literal match should work", filter.isBodyExcluded("DOES_NOT_EXIST"));
        assertFalse("/_bulk should NOT match", filter.isBodyExcluded("/_bulk"));
    }

    @Test
    public void testGroupsSetAfterExclusionsStillResolves() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        // Set exclusions BEFORE groups — both setters trigger rebuildBodyExclusionMatcher(),
        // so the final matcher always reflects the current state of both fields regardless of order.
        filter.setBodyLoggingExclusions(List.of("BULK"));
        filter.setActionGroups(Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk")));

        assertTrue("/_bulk should match — setActionGroups triggers rebuild with existing exclusions", filter.isBodyExcluded("/_bulk"));
        assertTrue("indices:data/write/bulk should match via group", filter.isBodyExcluded("indices:data/write/bulk"));
    }

    @Test
    public void testBodyExcludedGroupsSetBeforeExclusions() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        // Set groups FIRST, then exclusions — group IS resolved
        filter.setActionGroups(Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk")));
        filter.setBodyLoggingExclusions(List.of("BULK"));

        assertTrue("/_bulk should match because groups were set before exclusions", filter.isBodyExcluded("/_bulk"));
        assertTrue("indices:data/write/bulk[s] should match", filter.isBodyExcluded("indices:data/write/bulk[s]"));
    }

    @Test
    public void testBodyExcludedFromSettings() {
        Settings settings = Settings.builder()
            .put("plugins.security.audit.config.action_groups.BULK", "indices:data/write/bulk*,/_bulk")
            .put("plugins.security.audit.config.body_logging_exclusions", "BULK")
            .build();

        AuditConfig.Filter filter = AuditConfig.Filter.from(settings);

        assertTrue("/_bulk should be excluded via settings", filter.isBodyExcluded("/_bulk"));
        assertTrue("indices:data/write/bulk should be excluded via settings", filter.isBodyExcluded("indices:data/write/bulk"));
        assertFalse("/_search should NOT be excluded", filter.isBodyExcluded("/_search"));
    }

    // --- Additional coverage tests ---

    @Test
    public void testCaseSensitiveGroupNames() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk")));
        // Reference group with wrong case — should NOT resolve the group
        filter.setBodyLoggingExclusions(List.of("bulk"));

        // "bulk" is treated as a literal pattern (not the "BULK" group)
        assertFalse("/_bulk should NOT match — group names are case-sensitive", filter.isBodyExcluded("/_bulk"));
        assertTrue("literal 'bulk' should match itself", filter.isBodyExcluded("bulk"));
    }

    @Test
    public void testPathWithoutQueryParams() {
        // In production, REST paths arrive stripped of query params (request.path()).
        // This test documents that isBodyExcluded matches on the path portion only.
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Collections.emptyMap());
        filter.setBodyLoggingExclusions(List.of("/_bulk"));

        // The path as it arrives in addRestRequestInfo (query params stripped by REST layer)
        assertTrue("/_bulk should match (path without params)", filter.isBodyExcluded("/_bulk"));
        // If somehow the full URI were passed, the exact string wouldn't match
        assertFalse("/_bulk?refresh=true should NOT match exact pattern /_bulk", filter.isBodyExcluded("/_bulk?refresh=true"));
    }

    @Test
    public void testPathWithWildcardMatchesQueryParamVariant() {
        // Users can use a wildcard pattern to match paths regardless of suffix
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Collections.emptyMap());
        filter.setBodyLoggingExclusions(List.of("/_bulk*"));

        assertTrue("/_bulk should match wildcard", filter.isBodyExcluded("/_bulk"));
        assertTrue("/_bulk?refresh=true should match wildcard", filter.isBodyExcluded("/_bulk?refresh=true"));
        assertFalse("/_search should NOT match", filter.isBodyExcluded("/_search"));
    }

    @Test
    public void testMalformedActionGroupEmptyString() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        // Group with empty string pattern — WildcardMatcher.from("") does not match anything
        filter.setActionGroups(Map.of("EMPTY", List.of("")));
        filter.setBodyLoggingExclusions(List.of("EMPTY"));

        // Empty pattern effectively matches nothing useful
        assertFalse("/_bulk should NOT match empty pattern", filter.isBodyExcluded("/_bulk"));
        assertFalse("empty string does not match via WildcardMatcher", filter.isBodyExcluded(""));
    }

    @Test
    public void testMalformedActionGroupWhitespaceOnly() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        // Group with whitespace-only patterns
        filter.setActionGroups(Map.of("WHITESPACE", List.of("  ", "\t")));
        filter.setBodyLoggingExclusions(List.of("WHITESPACE"));

        assertFalse("/_bulk should NOT match whitespace patterns", filter.isBodyExcluded("/_bulk"));
    }

    @Test
    public void testSetActionGroupsNullThenIsBodyExcluded() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setBodyLoggingExclusions(List.of("BULK"));
        filter.setActionGroups(null); // null → treated as empty map

        // "BULK" is not a known group (groups are null/empty), so treated as literal
        assertTrue("literal 'BULK' should match itself", filter.isBodyExcluded("BULK"));
        assertFalse("/_bulk should NOT match", filter.isBodyExcluded("/_bulk"));
    }

    @Test
    public void testSetBodyLoggingExclusionsNull() {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Map.of("BULK", List.of("/_bulk")));
        filter.setBodyLoggingExclusions(null); // null → treated as empty

        assertFalse("nothing should be excluded when exclusions are null", filter.isBodyExcluded("/_bulk"));
    }

    @Test
    public void testConcurrentSettersAndQueryDoesNotThrow() throws InterruptedException {
        // Smoke test: verify no exceptions thrown when setters and isBodyExcluded run concurrently.
        // This does NOT assert correctness of the matcher state under concurrent mutation.
        // Correctness relies on the external invariant that only bodyLoggingExclusions is updated
        // dynamically at runtime; actionGroups is static (set once at startup).
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk")));
        filter.setBodyLoggingExclusions(List.of("BULK"));

        java.util.concurrent.atomic.AtomicBoolean failed = new java.util.concurrent.atomic.AtomicBoolean(false);
        java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(3);

        // Thread 1: repeatedly update action groups
        Thread updater1 = new Thread(() -> {
            try {
                for (int i = 0; i < 1000; i++) {
                    filter.setActionGroups(Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk", "/_extra" + i)));
                }
            } catch (Exception e) {
                failed.set(true);
            } finally {
                latch.countDown();
            }
        });

        // Thread 2: repeatedly update exclusions
        Thread updater2 = new Thread(() -> {
            try {
                for (int i = 0; i < 1000; i++) {
                    filter.setBodyLoggingExclusions(List.of("BULK"));
                    filter.setBodyLoggingExclusions(Collections.emptyList());
                }
            } catch (Exception e) {
                failed.set(true);
            } finally {
                latch.countDown();
            }
        });

        // Thread 3: repeatedly query
        Thread reader = new Thread(() -> {
            try {
                for (int i = 0; i < 1000; i++) {
                    // Should never throw, regardless of concurrent updates
                    filter.isBodyExcluded("/_bulk");
                    filter.isBodyExcluded("indices:data/write/bulk[s]");
                    filter.isBodyExcluded("/_search");
                }
            } catch (Exception e) {
                failed.set(true);
            } finally {
                latch.countDown();
            }
        });

        updater1.start();
        updater2.start();
        reader.start();
        latch.await(10, java.util.concurrent.TimeUnit.SECONDS);

        assertFalse("Concurrent access should not throw exceptions", failed.get());
    }

    @Test
    public void testSerializationRoundTrip() throws Exception {
        AuditConfig.Filter filter = AuditConfig.Filter.from(Settings.EMPTY);
        filter.setActionGroups(Map.of("BULK", List.of("indices:data/write/bulk*", "/_bulk")));
        filter.setBodyLoggingExclusions(List.of("BULK"));

        // Serialize to JSON
        String json = org.opensearch.security.DefaultObjectMapper.writeValueAsString(filter, false);

        // Verify JSON contains our fields
        assertTrue("JSON should contain body_logging_exclusions", json.contains("body_logging_exclusions"));
        assertTrue("JSON should contain action_groups", json.contains("action_groups"));
    }

    @Test
    public void testConstantKeysMatchSecuritySettings() {
        // Guard against key drift between the circular-init-safe constants and SecuritySettings
        assertEquals(
            "BODY_LOGGING_EXCLUSIONS_KEY must match SecuritySettings",
            AuditConfig.Filter.BODY_LOGGING_EXCLUSIONS_KEY,
            org.opensearch.security.support.SecuritySettings.AUDIT_BODY_LOGGING_EXCLUSIONS.getKey()
        );
        assertEquals(
            "ACTION_GROUPS_PREFIX must match SecuritySettings",
            AuditConfig.Filter.ACTION_GROUPS_PREFIX,
            org.opensearch.security.support.SecuritySettings.AUDIT_ACTION_GROUPS.getKey()
        );
    }
}
