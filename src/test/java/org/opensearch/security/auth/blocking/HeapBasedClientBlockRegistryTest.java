/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2015-2019 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.security.auth.blocking;

import java.util.Set;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class HeapBasedClientBlockRegistryTest {

    @Test
    public void simpleTest() throws Exception {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(50, 3, String.class);

        assertFalse(registry.isBlocked("a"));
        registry.block("a");
        assertTrue(registry.isBlocked("a"));

        registry.block("b");
        assertTrue(registry.isBlocked("a"));
        assertTrue(registry.isBlocked("b"));

        registry.block("c");
        assertTrue(registry.isBlocked("a"));
        assertTrue(registry.isBlocked("b"));
        assertTrue(registry.isBlocked("c"));

        registry.block("d");
        assertFalse(registry.isBlocked("a"));
        assertTrue(registry.isBlocked("b"));
        assertTrue(registry.isBlocked("c"));
        assertTrue(registry.isBlocked("d"));
    }

    @Test
    public void expiryTest() throws Exception {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(50, 3, String.class);

        assertFalse(registry.isBlocked("a"));
        registry.block("a");
        assertTrue(registry.isBlocked("a"));
        Thread.sleep(55);
        assertFalse(registry.isBlocked("a"));
    }

    /**
     * {@link HeapBasedClientBlockRegistry#block(Object, long)} with a future absolute expiry blocks
     * until that time and no longer.
     */
    @Test
    public void blockUntilAbsoluteExpiry() throws Exception {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(10_000, 100, String.class);

        long expiresAt = System.currentTimeMillis() + 60;
        registry.block("a", expiresAt);
        assertTrue(registry.isBlocked("a"));
        assertEquals(Long.valueOf(expiresAt), registry.expiresAtMs("a"));

        Thread.sleep(80);
        assertFalse("expired entry should no longer be blocked", registry.isBlocked("a"));
        assertNull("expiresAtMs should return null once expired", registry.expiresAtMs("a"));
    }

    /**
     * {@link HeapBasedClientBlockRegistry#block(Object, long)} with a past absolute expiry MUST NOT
     * mark the client as blocked. Otherwise a stale hydration would briefly block a client that
     * shouldn't be.
     */
    @Test
    public void blockWithPastExpiryIsNoOp() {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(10_000, 100, String.class);

        registry.block("a", System.currentTimeMillis() - 1000);
        assertFalse(registry.isBlocked("a"));
        assertNull(registry.expiresAtMs("a"));
    }

    /**
     * The cache-wide {@code expireAfterWrite} setting acts as a safety upper bound: a block written
     * with an absolute expiry beyond the registry's configured max block duration is capped at
     * {@code writeTime + maxBlockDuration}.
     */
    @Test
    public void cacheWideExpirySafetyUpperBound() throws Exception {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(50, 100, String.class);

        registry.block("a", System.currentTimeMillis() + 60_000); // request 1 minute
        assertTrue(registry.isBlocked("a"));

        Thread.sleep(80); // wait past the 50 ms safety bound
        assertFalse("safety upper bound should evict entry after cache-wide TTL", registry.isBlocked("a"));
    }

    /**
     * {@link HeapBasedClientBlockRegistry#unblock(Object)} removes an active block and is a no-op on
     * an unknown client.
     */
    @Test
    public void unblockRemovesActiveBlockAndIsNoOpOnUnknown() {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(10_000, 100, String.class);

        registry.block("a");
        assertTrue(registry.isBlocked("a"));
        registry.unblock("a");
        assertFalse(registry.isBlocked("a"));
        assertNull(registry.expiresAtMs("a"));

        // No-op path — must not throw.
        registry.unblock("never-blocked");
        assertFalse(registry.isBlocked("never-blocked"));
    }

    /**
     * {@link HeapBasedClientBlockRegistry#expiresAtMs(Object)} returns null for an unknown or expired
     * client and the exact recorded expiry for an active block.
     */
    @Test
    public void expiresAtMsReturnsNullForUnknownAndValueForActive() {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(10_000, 100, String.class);

        assertNull(registry.expiresAtMs("nope"));

        long expiresAt = System.currentTimeMillis() + 5_000;
        registry.block("a", expiresAt);
        Long recorded = registry.expiresAtMs("a");
        assertNotNull(recorded);
        assertEquals(Long.valueOf(expiresAt), recorded);
    }

    /**
     * {@link HeapBasedClientBlockRegistry#currentlyBlocked()} returns a snapshot of clients whose
     * block has not yet expired. Expired entries are omitted even if the underlying Guava cache
     * hasn't evicted them yet.
     */
    @Test
    public void currentlyBlockedReturnsOnlyActiveEntries() throws Exception {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(10_000, 100, String.class);

        assertEquals(Set.of(), registry.currentlyBlocked());

        registry.block("a", System.currentTimeMillis() + 5_000); // long-lived
        registry.block("b", System.currentTimeMillis() + 30);    // short-lived
        assertEquals(Set.of("a", "b"), registry.currentlyBlocked());

        Thread.sleep(50);
        // "b" is past its recorded expiry; currentlyBlocked must filter it out even though
        // the Guava cache-wide expireAfterWrite (10s) has not evicted it yet.
        assertEquals(Set.of("a"), registry.currentlyBlocked());
    }

    /**
     * A block that has already expired according to its stored {@code expiresAtMs} is invisible to
     * {@link HeapBasedClientBlockRegistry#isBlocked(Object)} on the very next call, even before the
     * cache-wide {@code expireAfterWrite} would have evicted it.
     */
    @Test
    public void perEntryExpirySupersedesCacheWideForEarlyExpiry() throws Exception {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(10_000, 100, String.class);

        registry.block("a", System.currentTimeMillis() + 30);
        assertTrue(registry.isBlocked("a"));
        Thread.sleep(50);
        assertFalse("per-entry expiry should short-circuit before cache-wide TTL", registry.isBlocked("a"));
    }

    /**
     * Legacy {@link HeapBasedClientBlockRegistry#block(Object)} respects the constructor-supplied
     * block duration.
     */
    @Test
    public void legacyBlockRespectsConstructorDuration() throws Exception {
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(30, 100, String.class);

        long before = System.currentTimeMillis();
        registry.block("a");
        Long expiresAt = registry.expiresAtMs("a");
        assertNotNull(expiresAt);
        // Expiry should be roughly [before + 30, now + 30]; allow a small window for scheduling.
        assertTrue("expiry too early: " + expiresAt, expiresAt >= before + 30);
        assertTrue("expiry too late: " + expiresAt, expiresAt <= System.currentTimeMillis() + 30);

        Thread.sleep(50);
        assertFalse(registry.isBlocked("a"));
    }
}
