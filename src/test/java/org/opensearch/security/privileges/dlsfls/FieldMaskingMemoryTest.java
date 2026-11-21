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

package org.opensearch.security.privileges.dlsfls;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.google.common.collect.ImmutableSet;
import org.apache.lucene.util.BytesRef;
import org.junit.Test;

import org.opensearch.common.settings.Settings;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assume.assumeTrue;

/**
 * Regression tests for issue #4031: field masking must not allocate a full copy of every masked
 * field value per document (and must not allocate a new hash instance per value), otherwise
 * searches over many documents with masked fields cause excessive heap usage / GC pressure.
 */
public class FieldMaskingMemoryTest {

    private static final FieldMasking.Config DEFAULT_CONFIG = FieldMasking.Config.fromSettings(Settings.EMPTY);

    // Known hash values for "foobar" (see FieldMaskingTest); used to verify that the reused
    // thread-local hash instances produce exactly the same results as fresh instances.
    private static final String BLAKE2B_FOOBAR = "c042e214a8b49561577445be44c188a8e6274006b36cd0c6fba5312253cf9293";
    private static final String BLAKE2B_LEGACY_FOOBAR = "96c8d1da7eb153db858d4f0585120319e17ed1162db9e94bee19fb10b6d19727";
    private static final String SHA256_FOOBAR = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";

    private static FieldMasking.FieldMaskingRule.Field blake2bField() throws Exception {
        return new FieldMasking.FieldMaskingRule.Field(new FieldMasking.FieldMaskingExpression("secret"), DEFAULT_CONFIG);
    }

    private static FieldMasking.FieldMaskingRule.Field sha256Field() throws Exception {
        return new FieldMasking.FieldMaskingRule.Field(new FieldMasking.FieldMaskingExpression("secret::SHA-256"), DEFAULT_CONFIG);
    }

    private static FieldMasking.FieldMaskingRule.Field legacyBlake2bField() throws Exception {
        FieldMasking.Config legacy = FieldMasking.Config.fromSettings(
            Settings.builder().put("plugins.security.masked_fields.algorithm.default", FieldMasking.Config.BLAKE2B_LEGACY_DEFAULT).build()
        );
        return new FieldMasking.FieldMaskingRule.Field(new FieldMasking.FieldMaskingExpression("secret"), legacy);
    }

    @Test
    public void applyBytesRefWithOffsetMatchesOtherOverloadsAndDoesNotModifyInput() throws Exception {
        FieldMasking.FieldMaskingRule.Field field = blake2bField();

        // BytesRef with a non-zero offset, as produced by Lucene doc values lookups
        byte[] backing = new byte[] { 0x00, 'f', 'o', 'o', 'b', 'a', 'r', 0x00 };
        byte[] backingCopy = backing.clone();
        BytesRef value = new BytesRef(backing, 1, 6);

        BytesRef masked = field.apply(value);

        assertThat(masked, notNullValue());
        assertThat(masked.utf8ToString(), equalTo(field.apply("foobar")));
        assertThat(
            masked.utf8ToString(),
            equalTo(new String(field.apply("foobar".getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8))
        );
        assertThat(masked.utf8ToString(), equalTo(BLAKE2B_FOOBAR));
        // The input value must not be modified by masking
        org.junit.Assert.assertArrayEquals(backingCopy, backing);
    }

    @Test
    public void applyNullBytesRefReturnsNull() throws Exception {
        assertThat(blake2bField().apply((BytesRef) null), nullValue());
    }

    @Test
    public void reusedThreadLocalHashesProduceStableResults() throws Exception {
        FieldMasking.FieldMaskingRule.Field blake2b = blake2bField();
        FieldMasking.FieldMaskingRule.Field sha256 = sha256Field();
        FieldMasking.FieldMaskingRule.Field legacy = legacyBlake2bField();

        // Interleave many invocations across different algorithms and fields to make sure the
        // reused thread-local digest instances are correctly reset between uses.
        for (int i = 0; i < 1000; i++) {
            assertThat(blake2b.apply("foobar"), equalTo(BLAKE2B_FOOBAR));
            assertThat(sha256.apply("foobar"), equalTo(SHA256_FOOBAR));
            assertThat(legacy.apply("foobar"), equalTo(BLAKE2B_LEGACY_FOOBAR));
            assertThat(blake2b.apply(new BytesRef("foobar")), equalTo(new BytesRef(BLAKE2B_FOOBAR)));
            assertThat(blake2b.apply("something else entirely " + i).length(), equalTo(64));
        }
    }

    @Test
    public void maskingLargeValuesDoesNotAllocateACopyOfTheInputPerValue() throws Exception {
        com.sun.management.ThreadMXBean threadMXBean = threadAllocatedMemoryBean();
        assumeTrue("thread allocated memory measurement not supported on this JVM", threadMXBean != null);

        // Use a custom hash algorithm (SHA-256): unlike Blake2b it does not allocate per input
        // block, so the measurement directly reflects the per-value overhead of the masking code.
        FieldMasking.FieldMaskingRule.Field field = sha256Field();

        final byte[] largeValue = new byte[64 * 1024];
        Arrays.fill(largeValue, (byte) 'x');
        final BytesRef value = new BytesRef(largeValue);

        // Warm up: initialize thread-locals and let the JIT compile the hot path
        long sink = 0;
        for (int i = 0; i < 500; i++) {
            sink += field.apply(value).length;
        }

        final int iterations = 2_000;
        final long before = threadMXBean.getThreadAllocatedBytes(Thread.currentThread().getId());
        for (int i = 0; i < iterations; i++) {
            // Prevent escape analysis from scalar-replacing the result
            sink += field.apply(value).length;
        }
        final long allocated = threadMXBean.getThreadAllocatedBytes(Thread.currentThread().getId()) - before;
        assertThat(sink > 0, is(true));

        // The masked result is a 64 character hex string. Masking one 64KB value must not allocate
        // anywhere near a full copy of the 64KB input (the old implementation allocated > 64KB per
        // value because of BytesRef.deepCopyOf plus a fresh MessageDigest and buffers per call).
        final long perValue = allocated / iterations;
        assertThat("masking a 64KB field value allocated " + perValue + " bytes per value on average", perValue < 4096, is(true));
    }

    @Test
    public void blake2bMaskingDoesNotAllocateAFullCopyOfTheInputPerValue() throws Exception {
        com.sun.management.ThreadMXBean threadMXBean = threadAllocatedMemoryBean();
        assumeTrue("thread allocated memory measurement not supported on this JVM", threadMXBean != null);

        FieldMasking.FieldMaskingRule.Field field = blake2bField();

        final byte[] largeValue = new byte[4096];
        Arrays.fill(largeValue, (byte) 'x');
        final BytesRef value = new BytesRef(largeValue);

        // Warm up: initialize thread-locals and let the JIT compile the hot path
        long sink = 0;
        for (int i = 0; i < 2_000; i++) {
            sink += field.apply(value).length;
        }

        final int iterations = 10_000;
        final long before = threadMXBean.getThreadAllocatedBytes(Thread.currentThread().getId());
        for (int i = 0; i < iterations; i++) {
            // Prevent escape analysis from scalar-replacing the result
            sink += field.apply(value).length;
        }
        final long allocated = threadMXBean.getThreadAllocatedBytes(Thread.currentThread().getId()) - before;
        assertThat(sink > 0, is(true));

        // Blake2b internally allocates a small buffer per 128 byte input block (~4KB for a 4KB
        // value), but the old implementation additionally allocated a full copy of the 4KB input
        // (BytesRef.deepCopyOf) plus a fresh Blake2b instance and output buffers per value
        // (> 9KB per value in total).
        final long perValue = allocated / iterations;
        assertThat("masking a 4KB field value allocated " + perValue + " bytes per value on average", perValue < 6144, is(true));
    }

    @Test
    public void filteringDocumentsMasksFieldsCorrectlyForLargeDocuments() throws Exception {
        FieldMasking.FieldMaskingRule fmRule = FieldMasking.FieldMaskingRule.of(DEFAULT_CONFIG, "secret");

        // Build a document whose filtered output is roughly as large as the input (large unmasked
        // field plus a masked field)
        StringBuilder sb = new StringBuilder("{\"secret\":\"foobar\",\"pad\":\"");
        for (int i = 0; i < 48 * 1024 - 100; i++) {
            sb.append('p');
        }
        sb.append("\"}");
        final byte[] document = sb.toString().getBytes(StandardCharsets.UTF_8);

        final byte[] result = FlsDocumentFilter.filter(document, FieldPrivileges.FlsRule.ALLOW_ALL, fmRule, ImmutableSet.of());

        // Correctness: the secret must be masked with the expected hash, the rest must be preserved
        final String resultString = new String(result, StandardCharsets.UTF_8);
        assertThat(resultString.contains("\"secret\":\"" + BLAKE2B_FOOBAR + "\""), is(true));
        assertThat(resultString.contains("\"pad\":\"pppp"), is(true));
        assertThat(resultString.contains("foobar"), is(false));
    }

    @Test
    public void filteringManyDocumentsDoesNotAccumulateState() throws Exception {
        // Regression test for unbounded accumulation while masking: filtering many documents in a
        // loop must produce identical results and must not retain per-document state on the rule.
        FieldMasking.FieldMaskingRule fmRule = FieldMasking.FieldMaskingRule.of(DEFAULT_CONFIG, "secret");
        final byte[] document = "{\"secret\":\"foobar\",\"n\":42}".getBytes(StandardCharsets.UTF_8);

        byte[] first = null;
        for (int i = 0; i < 1_000; i++) {
            final byte[] result = FlsDocumentFilter.filter(document, FieldPrivileges.FlsRule.ALLOW_ALL, fmRule, ImmutableSet.of());
            if (first == null) {
                first = result;
            } else {
                org.junit.Assert.assertArrayEquals(first, result);
            }
        }
        assertThat(new String(first, StandardCharsets.UTF_8), equalTo("{\"secret\":\"" + BLAKE2B_FOOBAR + "\",\"n\":42}"));
    }

    private static com.sun.management.ThreadMXBean threadAllocatedMemoryBean() {
        ThreadMXBean bean = ManagementFactory.getThreadMXBean();
        if (bean instanceof com.sun.management.ThreadMXBean sunBean && sunBean.isThreadAllocatedMemorySupported()) {
            sunBean.setThreadAllocatedMemoryEnabled(true);
            return sunBean;
        }
        return null;
    }
}
