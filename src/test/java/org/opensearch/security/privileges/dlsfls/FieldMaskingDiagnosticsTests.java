/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.privileges.dlsfls;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.lucene.tests.util.LuceneTestCase;

import org.opensearch.security.DefaultObjectMapper;

public class FieldMaskingDiagnosticsTests extends LuceneTestCase {
    public void testWarningsAreDeduplicatedAndRateLimited() {
        AtomicLong clock = new AtomicLong();
        var warnings = new ArrayList<FieldMaskingDiagnostics.Warning>();
        var diagnostics = new FieldMaskingDiagnostics(clock::get, warnings::add);
        diagnostics.report("index", "field", "integer", "_source");
        diagnostics.report("index", "field", "integer", "_source");
        diagnostics.report("index", "other", "boolean", "_source");
        assertEquals(1, warnings.size());
        clock.addAndGet(TimeUnit.MINUTES.toNanos(1));
        diagnostics.report("index", "field", "integer", "_source");
        assertEquals(1, warnings.size());
        diagnostics.report("index", "other", "boolean", "_source");
        assertEquals(2, warnings.size());
    }

    public void testDiagnosticIdentifiersAreBoundedAndSingleLine() {
        var warnings = new ArrayList<FieldMaskingDiagnostics.Warning>();
        new FieldMaskingDiagnostics(() -> 0L, warnings::add).report("index\nname", "x".repeat(500), "integer", "_source");
        assertEquals("index?name", warnings.get(0).index());
        assertEquals(256, warnings.get(0).field().length());
    }

    public void testMixedSourceValuesRemainUnchangedExceptStrings() throws Exception {
        // This is also the source shape for a keyword mapping that coerces numeric input at indexing time.
        var rule = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, "value");
        byte[] filtered = FlsDocumentFilter.filter(
            "{\"value\":[42,true,null,\"secret\"],\"hidden\":123}".getBytes(StandardCharsets.UTF_8),
            FieldPrivileges.FlsRule.of("~hidden"),
            rule,
            Set.of(),
            "test-index"
        );
        var result = DefaultObjectMapper.objectMapper().readTree(filtered);
        assertEquals(42, result.path("value").get(0).asInt());
        assertTrue(result.path("value").get(1).asBoolean());
        assertTrue(result.path("value").get(2).isNull());
        assertNotEquals("secret", result.path("value").get(3).asText());
        assertFalse(result.has("hidden"));
    }
}
