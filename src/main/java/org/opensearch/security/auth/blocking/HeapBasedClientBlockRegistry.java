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

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * In-memory {@link ClientBlockRegistry} backed by a Guava cache.
 * <p>
 * Each entry maps {@code clientId -> expiresAtMs} (the absolute epoch time at which the block should
 * expire). Two mechanisms keep the cache clean:
 * <ol>
 *   <li>{@link #isBlocked} checks the stored {@code expiresAtMs} on every read and opportunistically
 *       invalidates entries whose recorded expiry is in the past. This is what enforces per-entry
 *       expiry semantics — the primary correctness contract.</li>
 *   <li>Guava's {@code expireAfterWrite(maxBlockDurationMs)} evicts entries whose write time is older
 *       than the registry's configured block duration. This acts as a safety upper bound: no entry
 *       can live longer than {@code maxBlockDurationMs} from its write time regardless of what
 *       {@code expiresAtMs} says. Blocks written with a distant {@code expiresAtMs} are effectively
 *       capped at {@code writeTime + maxBlockDurationMs}.</li>
 * </ol>
 */
public class HeapBasedClientBlockRegistry<ClientIdType> implements ClientBlockRegistry<ClientIdType> {

    private final Logger log = LogManager.getLogger(this.getClass());

    private final Cache<ClientIdType, Long> cache;
    private final Class<ClientIdType> clientIdType;
    private final long maxBlockDurationMs;

    public HeapBasedClientBlockRegistry(long expiryMs, int maxEntries, Class<ClientIdType> clientIdType) {
        this.clientIdType = clientIdType;
        this.maxBlockDurationMs = expiryMs;
        this.cache = CacheBuilder.newBuilder()
            .expireAfterWrite(expiryMs, TimeUnit.MILLISECONDS)
            .maximumSize(maxEntries)
            .concurrencyLevel(4)
            .removalListener(new RemovalListener<ClientIdType, Long>() {
                @Override
                public void onRemoval(RemovalNotification<ClientIdType, Long> notification) {
                    if (log.isInfoEnabled()) {
                        log.info("Unblocking " + notification.getKey());
                    }
                }
            })
            .build();
    }

    @Override
    public boolean isBlocked(ClientIdType clientId) {
        Long expiresAtMs = cache.getIfPresent(clientId);
        if (expiresAtMs == null) {
            return false;
        }
        if (expiresAtMs <= System.currentTimeMillis()) {
            // Expired — opportunistically invalidate so a future getIfPresent short-circuits.
            cache.invalidate(clientId);
            return false;
        }
        return true;
    }

    @Override
    public void block(ClientIdType clientId) {
        block(clientId, System.currentTimeMillis() + maxBlockDurationMs);
    }

    @Override
    public void block(ClientIdType clientId, long expiresAtMs) {
        if (expiresAtMs <= System.currentTimeMillis()) {
            // Refuse to record a block that is already expired.
            return;
        }
        if (log.isInfoEnabled()) {
            log.info("Blocking " + clientId);
        }
        this.cache.put(clientId, expiresAtMs);
    }

    @Override
    public void unblock(ClientIdType clientId) {
        this.cache.invalidate(clientId);
    }

    @Override
    public Long expiresAtMs(ClientIdType clientId) {
        Long expiresAtMs = cache.getIfPresent(clientId);
        if (expiresAtMs == null) {
            return null;
        }
        if (expiresAtMs <= System.currentTimeMillis()) {
            cache.invalidate(clientId);
            return null;
        }
        return expiresAtMs;
    }

    @Override
    public Set<ClientIdType> currentlyBlocked() {
        long now = System.currentTimeMillis();
        Set<ClientIdType> result = new HashSet<>();
        for (Map.Entry<ClientIdType, Long> entry : cache.asMap().entrySet()) {
            Long expiresAtMs = entry.getValue();
            if (expiresAtMs != null && expiresAtMs > now) {
                result.add(entry.getKey());
            }
        }
        return Collections.unmodifiableSet(result);
    }

    @Override
    public Class<ClientIdType> getClientIdType() {
        return clientIdType;
    }

}
