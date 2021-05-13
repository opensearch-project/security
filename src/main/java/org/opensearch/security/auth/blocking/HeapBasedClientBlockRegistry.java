/*
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

import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

public class HeapBasedClientBlockRegistry<ClientIdType> implements ClientBlockRegistry<ClientIdType> {

    private final Logger log = LogManager.getLogger(this.getClass());

    private final Cache<ClientIdType, Long> cache;
    private final Class<ClientIdType> clientIdType;

    public HeapBasedClientBlockRegistry(long expiryMs, int maxEntries, Class<ClientIdType> clientIdType) {
        this.clientIdType = clientIdType;
        this.cache = CacheBuilder.newBuilder().expireAfterWrite(expiryMs, TimeUnit.MILLISECONDS).maximumSize(maxEntries).concurrencyLevel(4)
                .removalListener(new RemovalListener<ClientIdType, Long>() {
                    @Override
                    public void onRemoval(RemovalNotification<ClientIdType, Long> notification) {
                        if (log.isInfoEnabled()) {
                            log.info("Unblocking " + notification.getKey());
                        }
                    }
                }).build();
    }

    @Override
    public boolean isBlocked(ClientIdType clientId) {
        return cache.getIfPresent(clientId) != null;
    }

    @Override
    public void block(ClientIdType clientId) {
        if (log.isInfoEnabled()) {
            log.info("Blocking " + clientId);
        }

        this.cache.put(clientId, System.currentTimeMillis());
    }

    @Override
    public Class<ClientIdType> getClientIdType() {
        return clientIdType;
    }

}
