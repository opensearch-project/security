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

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.Assert;
import org.junit.Test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;

public class SelfRefreshingKeySetTest {

    @Test
    public void basicTest() throws AuthenticatorUnavailableException, BadCredentialsException {
        SelfRefreshingKeySet selfRefreshingKeySet = new SelfRefreshingKeySet(new MockKeySetProvider());

        OctetSequenceKey key1 = (OctetSequenceKey) selfRefreshingKeySet.getKey("kid/a");
        Assert.assertEquals(TestJwk.OCT_1_K, key1.getKeyValue().decodeToString());
        Assert.assertEquals(1, selfRefreshingKeySet.getRefreshCount());

        OctetSequenceKey key2 = (OctetSequenceKey) selfRefreshingKeySet.getKey("kid/b");
        Assert.assertEquals(TestJwk.OCT_2_K, key2.getKeyValue().decodeToString());
        Assert.assertEquals(1, selfRefreshingKeySet.getRefreshCount());

        try {
            selfRefreshingKeySet.getKey("kid/X");
            Assert.fail("Expected a BadCredentialsException");
        } catch (BadCredentialsException e) {
            Assert.assertEquals(2, selfRefreshingKeySet.getRefreshCount());
        }

    }

    @Test(timeout = 10000)
    public void twoThreadedTest() throws Exception {
        BlockingMockKeySetProvider provider = new BlockingMockKeySetProvider();

        final SelfRefreshingKeySet selfRefreshingKeySet = new SelfRefreshingKeySet(provider);

        ExecutorService executorService = Executors.newCachedThreadPool();

        Future<JWK> f1 = executorService.submit(() -> selfRefreshingKeySet.getKey("kid/a"));

        provider.waitForCalled();

        Future<JWK> f2 = executorService.submit(() -> selfRefreshingKeySet.getKey("kid/b"));

        while (selfRefreshingKeySet.getQueuedGetCount() == 0) {
            Thread.sleep(10);
        }

        provider.unblock();

        Assert.assertEquals(TestJwk.OCT_1_K, ((OctetSequenceKey) f1.get()).getKeyValue().decodeToString());
        Assert.assertEquals(TestJwk.OCT_2_K, ((OctetSequenceKey) f2.get()).getKeyValue().decodeToString());

        Assert.assertEquals(1, selfRefreshingKeySet.getRefreshCount());
        Assert.assertEquals(1, selfRefreshingKeySet.getQueuedGetCount());

    }

    static class MockKeySetProvider implements KeySetProvider {

        @Override
        public JWKSet get() throws AuthenticatorUnavailableException {
            return TestJwk.OCT_1_2_3;
        }

    }

    static class BlockingMockKeySetProvider extends MockKeySetProvider {
        private boolean blocked = true;
        private boolean called = false;

        @Override
        public synchronized JWKSet get() throws AuthenticatorUnavailableException {

            called = true;
            notifyAll();

            waitForUnblock();

            return super.get();
        }

        public synchronized void unblock() {
            blocked = false;
            notifyAll();
        }

        public synchronized void waitForCalled() throws InterruptedException {
            while (!called) {
                wait();
            }
        }

        private synchronized void waitForUnblock() {
            while (blocked) {
                try {
                    wait();
                } catch (InterruptedException e) {}

            }
        }
    }
}
