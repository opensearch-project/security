/*
 * Copyright OpenSearch Contributors
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

import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.common.base.Strings;

public class SelfRefreshingKeySet implements KeyProvider {
	private static final Logger log = LogManager.getLogger(SelfRefreshingKeySet.class);

	private final KeySetProvider keySetProvider;
	private final ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(1, 10, 1000, TimeUnit.MILLISECONDS,
			new LinkedBlockingQueue<Runnable>());
	private volatile JsonWebKeys jsonWebKeys = new JsonWebKeys();
	private boolean refreshInProgress = false;
	private long refreshCount = 0;
	private long queuedGetCount = 0;
	private long recentRefreshCount = 0;
	private long refreshTime = 0;
	private Throwable lastRefreshFailure = null;
	private int requestTimeoutMs = 5000;
	private int queuedThreadTimeoutMs = 2500;
	private int refreshRateLimitTimeWindowMs = 10000;
	private int refreshRateLimitCount = 10;

	public SelfRefreshingKeySet(KeySetProvider refreshFunction) {
		this.keySetProvider = refreshFunction;
	}

	public JsonWebKey getKey(String kid) throws AuthenticatorUnavailableException, BadCredentialsException {
		if (Strings.isNullOrEmpty(kid)) {
			return getKeyWithoutKeyId();
		} else {
			return getKeyWithKeyId(kid);
		}
	}

	public synchronized JsonWebKey getKeyAfterRefresh(String kid)
			throws AuthenticatorUnavailableException, BadCredentialsException {
		JsonWebKey result = getKeyAfterRefreshInternal(kid);

		if (result != null) {
			return result;
		} else if (jsonWebKeys.getKeys().size() == 0) {
			throw new AuthenticatorUnavailableException("No JWK are available from IdP");
		} else {
			throw new BadCredentialsException("JWT did not contain KID which is required if IdP provides multiple JWK");
		}
	}

	private synchronized JsonWebKey getKeyAfterRefreshInternal(String kid) throws AuthenticatorUnavailableException {
		if (refreshInProgress) {
			return waitForRefreshToFinish(kid);
		} else {
			return performRefresh(kid);
		}
	}

	private JsonWebKey getKeyWithoutKeyId() throws AuthenticatorUnavailableException, BadCredentialsException {
		List<JsonWebKey> keys = jsonWebKeys.getKeys();

		if (keys == null || keys.size() == 0) {
			JsonWebKey result = getKeyWithRefresh(null);

			if (result != null) {
				return result;
			} else {
				throw new AuthenticatorUnavailableException("No JWK are available from IdP");
			}
		} else if (keys.size() == 1) {
			return keys.get(0);
		} else {
			JsonWebKey result = getKeyWithRefresh(null);

			if (result != null) {
				return result;
			} else {
				throw new BadCredentialsException(
						"JWT did not contain KID which is required if IdP provides multiple JWK");
			}
		}
	}

	private JsonWebKey getKeyWithKeyId(String kid) throws AuthenticatorUnavailableException, BadCredentialsException {
		JsonWebKey result = jsonWebKeys.getKey(kid);

		if (result != null) {
			return result;
		}

		result = getKeyWithRefresh(kid);

		if (result == null) {
			throw new BadCredentialsException("Unknown kid " + kid);
		}

		return result;
	}

	private synchronized JsonWebKey getKeyWithRefresh(String kid) throws AuthenticatorUnavailableException {

		// Always re-check within synchronized to handle any races

		JsonWebKey result = getKeySimple(kid);

		if (result != null) {
			return result;
		}

		return getKeyAfterRefreshInternal(kid);
	}

	private JsonWebKey getKeySimple(String kid) {
		if (Strings.isNullOrEmpty(kid)) {
			List<JsonWebKey> keys = jsonWebKeys.getKeys();

			if (keys != null && keys.size() == 1) {
				return keys.get(0);
			} else {
				return null;
			}

		} else {
			return jsonWebKeys.getKey(kid);
		}
	}

	private synchronized JsonWebKey waitForRefreshToFinish(String kid) {
		queuedGetCount++;
		long currentRefreshCount = refreshCount;

		try {
			wait(queuedThreadTimeoutMs);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			log.debug(e);
		}

		// Just be optimistic and re-check the key

		JsonWebKey result = getKeySimple(kid);

		if (result != null) {
			return result;
		}

		if (refreshInProgress && currentRefreshCount == refreshCount) {
			// The wait() call returned due to the timeout.
			throw new AuthenticatorUnavailableException("Authentication backend timed out");
		} else if (lastRefreshFailure != null) {
			throw new AuthenticatorUnavailableException("Authentication backend failed", lastRefreshFailure);
		} else {
			// Refresh was successful, but we did not get a matching key
			return null;
		}
	}

	private synchronized JsonWebKey performRefresh(String kid) {
		if (log.isDebugEnabled()) {
			log.debug("performRefresh({})", kid);
		}

		final boolean recentRefresh;

		if (System.currentTimeMillis() - refreshTime < refreshRateLimitTimeWindowMs) {
			recentRefreshCount++;
			recentRefresh = true;

			if (recentRefreshCount > refreshRateLimitCount) {
				throw new AuthenticatorUnavailableException("Too many unknown kids recently: " + recentRefreshCount);
			}
		} else {
			recentRefresh = false;
		}

		refreshInProgress = true;
		refreshCount++;

		log.info("Performing refresh {}", refreshCount);

		long currentRefreshCount = refreshCount;

		try {

			Future<?> future = threadPoolExecutor.submit(new Runnable() {

				@Override
				public void run() {
					try {
						JsonWebKeys newKeys = keySetProvider.get();

						if (newKeys == null) {
							throw new RuntimeException("Refresh function " + keySetProvider + " yielded null");
						}

						log.info("KeySetProvider finished");

						synchronized (SelfRefreshingKeySet.this) {
							jsonWebKeys = newKeys;
							refreshInProgress = false;
							lastRefreshFailure = null;
							SelfRefreshingKeySet.this.notifyAll();
						}
					} catch (Throwable e) {
						synchronized (SelfRefreshingKeySet.this) {
							lastRefreshFailure = e;
							refreshInProgress = false;
							SelfRefreshingKeySet.this.notifyAll();
						}
						log.warn("KeySetProvider threw error", e);
					} finally {
						if (!recentRefresh) {
							recentRefreshCount = 0;
							refreshTime = System.currentTimeMillis();
						}
					}

				}
			});

			try {
				wait(requestTimeoutMs);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				log.debug(e);
			}

			JsonWebKey result = getKeySimple(kid);

			if (result != null) {
				return result;
			}

			if (refreshInProgress && currentRefreshCount == refreshCount) {
				if (!future.isDone()) {
					future.cancel(true);
				}

				lastRefreshFailure = new AuthenticatorUnavailableException("Authentication backend timed out");

				throw new AuthenticatorUnavailableException("Authentication backend timed out");
			}

			if (lastRefreshFailure != null) {
				throw new AuthenticatorUnavailableException("Authentication backend failed", lastRefreshFailure);
			}

			return null;

		} catch (RejectedExecutionException e) {
			throw new AuthenticatorUnavailableException("Did not try to call authentication backend because of "
					+ threadPoolExecutor.getActiveCount() + " pending threads", e);
		} finally {
			if (refreshInProgress && currentRefreshCount == refreshCount) {
				refreshInProgress = false;
				notifyAll();
			}
		}
	}

	public int getRequestTimeoutMs() {
		return requestTimeoutMs;
	}

	public void setRequestTimeoutMs(int requestTimeoutMs) {
		this.requestTimeoutMs = requestTimeoutMs;
	}

	public int getQueuedThreadTimeoutMs() {
		return queuedThreadTimeoutMs;
	}

	public void setQueuedThreadTimeoutMs(int queuedThreadTimeoutMs) {
		this.queuedThreadTimeoutMs = queuedThreadTimeoutMs;
	}

	public long getRefreshCount() {
		return refreshCount;
	}

	public long getQueuedGetCount() {
		return queuedGetCount;
	}

	public int getRefreshRateLimitTimeWindowMs() {
		return refreshRateLimitTimeWindowMs;
	}

	public void setRefreshRateLimitTimeWindowMs(int refreshRateLimitTimeWindowMs) {
		this.refreshRateLimitTimeWindowMs = refreshRateLimitTimeWindowMs;
	}

	public int getRefreshRateLimitCount() {
		return refreshRateLimitCount;
	}

	public void setRefreshRateLimitCount(int refreshRateLimitCount) {
		this.refreshRateLimitCount = refreshRateLimitCount;
	}
}
