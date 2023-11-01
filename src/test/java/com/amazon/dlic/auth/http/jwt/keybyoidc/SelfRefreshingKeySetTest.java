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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;

public class SelfRefreshingKeySetTest {

    private SelfRefreshingKeySet selfRefreshingKeySet;

    @Before
    public void setUp() {
        selfRefreshingKeySet = new SelfRefreshingKeySet(new MockKeySetProvider());
    }

    @Test
    public void getKey_withKidShouldReturnValidKey() throws AuthenticatorUnavailableException, BadCredentialsException {

        OctetSequenceKey key = (OctetSequenceKey) selfRefreshingKeySet.getKey("kid/a");
        assertThat(TestJwk.OCT_1_K, is(equalTo(key.getKeyValue().decodeToString())));
    }

    @Test
    public void getKey_withNullKidShouldThrowAuthenticatorUnavailableException() throws AuthenticatorUnavailableException,
        BadCredentialsException {

        Assert.assertThrows(AuthenticatorUnavailableException.class, () -> selfRefreshingKeySet.getKey(null));

    }

    @Test
    public void getKey_withInvalidDataShouldReturnBadCredentialException() throws AuthenticatorUnavailableException,
        BadCredentialsException {

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
            executor.submit(() -> {
                synchronized (lock) {
                    try {
                        selfRefreshingKeySet.getKeyAfterRefresh("kid/a");
                    } catch (AuthenticatorUnavailableException e) {} catch (BadCredentialsException e) {}
                }
            });
        }

        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.SECONDS);

        assertThat((int) selfRefreshingKeySet.getRefreshCount(), is(equalTo(numThreads)));
        assertThat((int) selfRefreshingKeySet.getQueuedGetCount(), is(equalTo((0))));
    }

    @Test
    public void getKeyAfterRefresh_withNullKidShouldThrowBadCredentialsException() throws AuthenticatorUnavailableException,
        BadCredentialsException {

        Assert.assertThrows(BadCredentialsException.class, () -> selfRefreshingKeySet.getKeyAfterRefresh(null));
    }

    @Test
    public void getKeyAfterRefresh_withInvalidDataShouldReturnBadCredentialException() throws AuthenticatorUnavailableException,
        BadCredentialsException {

        Assert.assertThrows(BadCredentialsException.class, () -> selfRefreshingKeySet.getKeyAfterRefresh("kid/X"));
    }

    static class MockKeySetProvider implements KeySetProvider {

        @Override
        public JWKSet get() throws AuthenticatorUnavailableException {
            return TestJwk.OCT_1_2_3;
        }
    }
}
