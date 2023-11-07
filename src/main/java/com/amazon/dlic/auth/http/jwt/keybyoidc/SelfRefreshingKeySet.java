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

import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

public class SelfRefreshingKeySet implements KeyProvider {
    private static final Logger log = LogManager.getLogger(SelfRefreshingKeySet.class);

    private final KeySetProvider keySetProvider;
    private final ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(
        1,
        10,
        1000,
        TimeUnit.MILLISECONDS,
        new LinkedBlockingQueue<Runnable>()
    );
    private volatile JWKSet jsonWebKeys = new JWKSet();
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

    public JWK getKey(String kid) throws AuthenticatorUnavailableException, BadCredentialsException {
        if (Strings.isNullOrEmpty(kid)) {
            return getKeyWithoutKeyId();
        } else {
            return getKeyWithKeyId(kid);
        }
    }

    public synchronized JWK getKeyAfterRefresh(String kid) throws AuthenticatorUnavailableException, BadCredentialsException {
        JWK result = getKeyAfterRefreshInternal(kid);

        if (result != null) {
            return result;
        } else if (jsonWebKeys.getKeys().size() == 0) {
            throw new AuthenticatorUnavailableException("No JWK are available from IdP");
        } else {
            throw new BadCredentialsException("JWT did not contain KID which is required if IdP provides multiple JWK");
        }
    }

    private synchronized JWK getKeyAfterRefreshInternal(String kid) throws AuthenticatorUnavailableException {
        if (refreshInProgress) {
            return waitForRefreshToFinish(kid);
        } else {
            return performRefresh(kid);
        }
    }

    private JWK getKeyWithoutKeyId() throws AuthenticatorUnavailableException, BadCredentialsException {
        List<JWK> keys = jsonWebKeys.getKeys();

        if (keys == null || keys.size() == 0) {
            JWK result = getKeyWithRefresh(null);

            if (result != null) {
                return result;
            } else {
                throw new AuthenticatorUnavailableException("No JWK are available from IdP");
            }
        } else if (keys.size() == 1) {
            return keys.get(0);
        } else {
            JWK result = getKeyWithRefresh(null);

            if (result != null) {
                return result;
            } else {
                throw new BadCredentialsException("JWT did not contain KID which is required if IdP provides multiple JWK");
            }
        }
    }

    private JWK getKeyWithKeyId(String kid) throws AuthenticatorUnavailableException, BadCredentialsException {
        JWK result = jsonWebKeys.getKeyByKeyId(kid);

        if (result != null) {
            return result;
        }

        result = getKeyWithRefresh(kid);

        if (result == null) {
            throw new BadCredentialsException("Unknown kid " + kid);
        }

        return result;
    }

    private synchronized JWK getKeyWithRefresh(String kid) throws AuthenticatorUnavailableException {

        // Always re-check within synchronized to handle any races

        JWK result = getKeySimple(kid);

        if (result != null) {
            return result;
        }

        return getKeyAfterRefreshInternal(kid);
    }

    private JWK getKeySimple(String kid) {
        if (Strings.isNullOrEmpty(kid)) {
            List<JWK> keys = jsonWebKeys.getKeys();

            if (keys != null && keys.size() == 1) {
                return keys.get(0);
            } else {
                return null;
            }

        } else {
            return jsonWebKeys.getKeyByKeyId(kid);
        }
    }

    private synchronized JWK waitForRefreshToFinish(String kid) {
        queuedGetCount++;
        long currentRefreshCount = refreshCount;

        try {
            wait(queuedThreadTimeoutMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.debug(e.toString());
        }

        // Just be optimistic and re-check the key

        JWK result = getKeySimple(kid);

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

    private synchronized JWK performRefresh(String kid) {
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
                        JWKSet newKeys = keySetProvider.get();

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
                log.debug(e.toString());
            }

            JWK result = getKeySimple(kid);

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
            throw new AuthenticatorUnavailableException(
                "Did not try to call authentication backend because of " + threadPoolExecutor.getActiveCount() + " pending threads",
                e
            );
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
