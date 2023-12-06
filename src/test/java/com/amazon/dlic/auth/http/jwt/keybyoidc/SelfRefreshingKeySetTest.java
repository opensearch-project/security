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
import static org.junit.Assert.fail;

public class SelfRefreshingKeySetTest {

    private SelfRefreshingKeySet selfRefreshingKeySet;
    private String keyForKidA;
    private String keyForKidB;
    private int numThreads = 10;

    @Before
    public void setUp() throws AuthenticatorUnavailableException, BadCredentialsException {
        selfRefreshingKeySet = new SelfRefreshingKeySet(new MockKeySetProvider());
        keyForKidA = TestJwk.OCT_1_K;
        keyForKidB = TestJwk.OCT_2_K;
    }

    @Test
    public void getKey_withKidShouldReturnValidKey() throws AuthenticatorUnavailableException, BadCredentialsException {

        OctetSequenceKey key = (OctetSequenceKey) selfRefreshingKeySet.getKey("kid/a");
        assertThat(keyForKidA, is(equalTo(key.getKeyValue().decodeToString())));
    }

    @Test
    public void getKey__withNullOrInvalidKidShouldThrowAnException() throws AuthenticatorUnavailableException, BadCredentialsException {

        Assert.assertThrows(AuthenticatorUnavailableException.class, () -> selfRefreshingKeySet.getKey(null));
        Assert.assertThrows(BadCredentialsException.class, () -> selfRefreshingKeySet.getKey("kid/X"));
    }

    @Test
    public void getKeyAfterRefresh_withKidShouldReturnKey() throws AuthenticatorUnavailableException, BadCredentialsException {

        OctetSequenceKey key = (OctetSequenceKey) selfRefreshingKeySet.getKeyAfterRefresh("kid/b");
        assertThat(keyForKidB, is(equalTo(key.getKeyValue().decodeToString())));
    }

    @Test
    public void getKeyAfterRefresh_withMultipleCallsShouldIncreaseQueueCount() throws InterruptedException, ExecutionException {
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        String[] keys = new String[] { "kid/a", "kid/b" };
        for (int i = 0; i < numThreads; i++) {
            // Using executor to make multiple asynchronous calls to method getKeyAfterRefresh, so queuedGetCount gets increased.
            // Without executor block, getKeyAfterRefresh method would be called once on each iteration in the main thread and wait for the
            // task to complete before continuing the loop, so queuedGetCount would not have pending tasks.
            executor.execute(() -> {
                try {
                    int indexKey = (int) (Math.random() * 2);
                    String keyToCompare = indexKey == 0 ? keyForKidA : keyForKidB;
                    OctetSequenceKey key = (OctetSequenceKey) selfRefreshingKeySet.getKeyAfterRefresh(keys[indexKey]);

                    assertThat(key, is(notNullValue()));
                    assertThat(keyToCompare, is(equalTo(key.getKeyValue().decodeToString())));
                } catch (AuthenticatorUnavailableException | BadCredentialsException e) {
                    fail("No exception was expected but found: " + e.getMessage());
                }
            });
        }

        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.SECONDS);

        assertThat((int) selfRefreshingKeySet.getRefreshCount(), is(greaterThan(0)));
        assertThat((int) selfRefreshingKeySet.getQueuedGetCount(), is(greaterThan(0)));
    }

    @Test
    public void getKeyAfterRefresh_withNullOrInvalidKidShouldThrowBadCredentialsException() {

        Assert.assertThrows(BadCredentialsException.class, () -> selfRefreshingKeySet.getKeyAfterRefresh(null));
        Assert.assertThrows(BadCredentialsException.class, () -> selfRefreshingKeySet.getKeyAfterRefresh("kid/X"));
    }

    static class MockKeySetProvider implements KeySetProvider {

        @Override
        public JWKSet get() throws AuthenticatorUnavailableException {
            return TestJwk.OCT_1_2_3;
        }
    }
}
