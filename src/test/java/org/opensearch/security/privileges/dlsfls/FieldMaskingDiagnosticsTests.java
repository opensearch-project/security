/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.privileges.dlsfls;

import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.lucene.tests.util.LuceneTestCase;

public class FieldMaskingDiagnosticsTests extends LuceneTestCase {
    public void testWarningsAreDeduplicatedAndRateLimited() {
        AtomicLong clock = new AtomicLong();
        var warnings = new ArrayList<FieldMaskingDiagnostics.Warning>();
        var diagnostics = new FieldMaskingDiagnostics(clock::get, warnings::add);
        diagnostics.report("index", "field", "integer", "role mapping inspection");
        diagnostics.report("index", "field", "integer", "role mapping inspection");
        diagnostics.report("index", "other", "boolean", "role mapping inspection");
        assertEquals(1, warnings.size());
        clock.addAndGet(TimeUnit.MINUTES.toNanos(1));
        diagnostics.report("index", "field", "integer", "role mapping inspection");
        assertEquals(1, warnings.size());
        diagnostics.report("index", "other", "boolean", "role mapping inspection");
        assertEquals(2, warnings.size());
    }

    public void testDiagnosticIdentifiersAreBoundedAndSingleLine() {
        var warnings = new ArrayList<FieldMaskingDiagnostics.Warning>();
        new FieldMaskingDiagnostics(() -> 0L, warnings::add).report("index\nname", "x".repeat(500), "integer", "role mapping inspection");
        assertEquals("index?name", warnings.get(0).index());
        assertEquals(256, warnings.get(0).field().length());
    }

}
