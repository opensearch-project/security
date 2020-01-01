/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.dlic.auth.http.jwt.keybyoidc.AuthenticatorUnavailableException;
import com.amazon.dlic.auth.http.jwt.keybyoidc.BadCredentialsException;
import com.amazon.dlic.auth.http.jwt.keybyoidc.KeySetProvider;
import com.amazon.dlic.auth.http.jwt.keybyoidc.SelfRefreshingKeySet;

public class SelfRefreshingKeySetTest {

	@Test
	public void basicTest() throws AuthenticatorUnavailableException, BadCredentialsException {
		SelfRefreshingKeySet selfRefreshingKeySet = new SelfRefreshingKeySet(new MockKeySetProvider());

		JsonWebKey key1 = selfRefreshingKeySet.getKey("kid/a");
		Assert.assertEquals(TestJwk.OCT_1_K, key1.getProperty("k"));
		Assert.assertEquals(1, selfRefreshingKeySet.getRefreshCount());

		JsonWebKey key2 = selfRefreshingKeySet.getKey("kid/b");
		Assert.assertEquals(TestJwk.OCT_2_K, key2.getProperty("k"));
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

		Future<JsonWebKey> f1 = executorService.submit(() -> selfRefreshingKeySet.getKey("kid/a"));

		provider.waitForCalled();

		Future<JsonWebKey> f2 = executorService.submit(() -> selfRefreshingKeySet.getKey("kid/b"));

		while (selfRefreshingKeySet.getQueuedGetCount() == 0) {
			Thread.sleep(10);
		}

		provider.unblock();

		Assert.assertEquals(TestJwk.OCT_1_K, f1.get().getProperty("k"));
		Assert.assertEquals(TestJwk.OCT_2_K, f2.get().getProperty("k"));

		Assert.assertEquals(1, selfRefreshingKeySet.getRefreshCount());
		Assert.assertEquals(1, selfRefreshingKeySet.getQueuedGetCount());

	}

	static class MockKeySetProvider implements KeySetProvider {

		@Override
		public JsonWebKeys get() throws AuthenticatorUnavailableException {
			return TestJwk.OCT_1_2_3;
		}

	}

	static class BlockingMockKeySetProvider extends MockKeySetProvider {
		private boolean blocked = true;
		private boolean called = false;

		@Override
		public synchronized JsonWebKeys get() throws AuthenticatorUnavailableException {

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
				} catch (InterruptedException e) {
				}

			}
		}
	}
}
