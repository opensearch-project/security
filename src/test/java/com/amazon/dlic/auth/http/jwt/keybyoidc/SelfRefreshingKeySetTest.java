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

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

public class SelfRefreshingKeySetTest {

    private SelfRefreshingKeySet selfRefreshingKeySet;
    private OctetSequenceKey keyForKidA;

    @Before
    public void setUp() throws AuthenticatorUnavailableException, BadCredentialsException {
        selfRefreshingKeySet = new SelfRefreshingKeySet(new MockKeySetProvider());
        keyForKidA = (OctetSequenceKey) selfRefreshingKeySet.getKey("kid/a");
    }

    @Test
    public void getKey_withKidShouldReturnValidKey() throws AuthenticatorUnavailableException, BadCredentialsException {

        OctetSequenceKey key = (OctetSequenceKey) selfRefreshingKeySet.getKey("kid/a");
        assertThat(TestJwk.OCT_1_K, is(equalTo(key.getKeyValue().decodeToString())));
    }

    @Test
    public void getKey__withNullOrInvaludKidShouldThrowBadCredentialsException() throws AuthenticatorUnavailableException,
        BadCredentialsException {

        Assert.assertThrows(BadCredentialsException.class, () -> selfRefreshingKeySet.getKey(null));
        Assert.assertThrows(BadCredentialsException.class, () -> selfRefreshingKeySet.getKey("kid/X"));
    }

    @Test
    public void getKeyAfterRefresh_withKidShouldReturnKey() throws AuthenticatorUnavailableException, BadCredentialsException {

        OctetSequenceKey key = (OctetSequenceKey) selfRefreshingKeySet.getKeyAfterRefresh("kid/b");
        assertThat(TestJwk.OCT_2_K, is(equalTo(key.getKeyValue().decodeToString())));
    }

    @Test
    public void getKeyAfterRefresh_queuedGetCountVariableShouldBeZeroWhenFinishWithAllKeyRefreshes() throws InterruptedException,
        ExecutionException {

        int numThreads = 10;
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        Object lock = new Object();

        for (int i = 0; i < numThreads; i++) {
            executor.execute(() -> {
                synchronized (lock) {
                    try {
                        OctetSequenceKey key = (OctetSequenceKey) selfRefreshingKeySet.getKeyAfterRefresh("kid/a");
                        assertThat(key, is(notNullValue()));
                        assertThat(keyForKidA, is(equalTo(key)));
                    } catch (AuthenticatorUnavailableException e) {} catch (BadCredentialsException e) {}
                }
            });
        }

        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);

        assertThat((int) selfRefreshingKeySet.getRefreshCount(), is(greaterThan(0)));
        assertThat((int) selfRefreshingKeySet.getQueuedGetCount(), is(equalTo((0))));
    }

    @Test
    public void getKeyAfterRefresh_withNullOrInvaludKidShouldThrowBadCredentialsException() {

        Assert.assertThrows(BadCredentialsException.class, () -> selfRefreshingKeySet.getKeyAfterRefresh(null));
        Assert.assertThrows(BadCredentialsException.class, () -> selfRefreshingKeySet.getKeyAfterRefresh("kid/X"));
    }

    static class MockKeySetProvider implements KeySetProvider {

        @Override
        public JWKSet get() throws AuthenticatorUnavailableException {
            return TestJwk.OCT_1_2_3;
        }
    }

    @Test
    public void getKeyAfterRefresh_queueShouldHavePendingTasks() throws InterruptedException, ExecutionException {

        int numThreads = 10;
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        for (int i = 0; i < numThreads; i++) {
            // Using executor to make asynchronous calls to getKeyAfterRefresh method, so the queue would have pending tasks added to it.
            // Without the executor block, getKeyAfterRefresh method would be called once on each iteration in the main thread and wait for
            // the task to complete before continuing the loop, so the queue would have no pending tasks at the end.
            executor.execute(() -> {
                try {
                    selfRefreshingKeySet.getKeyAfterRefresh("kid/a");
                } catch (AuthenticatorUnavailableException e) {} catch (BadCredentialsException e) {}
            });
        }

        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.SECONDS);

        // There is at least 1 refreshing key in progress.
        assertThat((int) selfRefreshingKeySet.getRefreshCount(), is(greaterThan(0)));
        // The queue should have at least 1 pending call waiting to start refreshing the key.
        assertThat((int) selfRefreshingKeySet.getQueuedGetCount(), is(greaterThan(0)));
    }
}
