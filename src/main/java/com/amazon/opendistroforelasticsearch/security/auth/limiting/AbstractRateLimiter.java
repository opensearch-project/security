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

package com.amazon.opendistroforelasticsearch.security.auth.limiting;

import java.net.InetAddress;
import java.nio.file.Path;

import org.opensearch.common.settings.Settings;

import com.amazon.opendistroforelasticsearch.security.auth.AuthFailureListener;
import com.amazon.opendistroforelasticsearch.security.auth.blocking.ClientBlockRegistry;
import com.amazon.opendistroforelasticsearch.security.auth.blocking.HeapBasedClientBlockRegistry;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.util.ratetracking.RateTracker;

public abstract class AbstractRateLimiter<ClientIdType> implements AuthFailureListener, ClientBlockRegistry<ClientIdType> {
    protected final ClientBlockRegistry<ClientIdType> clientBlockRegistry;
    protected final RateTracker<ClientIdType> rateTracker;

    public AbstractRateLimiter(Settings settings, Path configPath, Class<ClientIdType> clientIdType) {
        this.clientBlockRegistry = new HeapBasedClientBlockRegistry<>(settings.getAsInt("block_expiry_seconds", 60 * 10) * 1000,
                settings.getAsInt("max_blocked_clients", 100_000), clientIdType);
        this.rateTracker = RateTracker.create(settings.getAsInt("time_window_seconds", 60 * 60) * 1000, settings.getAsInt("allowed_tries", 10),
                settings.getAsInt("max_tracked_clients", 100_000));
    }

    @Override
    public abstract void onAuthFailure(InetAddress remoteAddress, AuthCredentials authCredentials, Object request);

    @Override
    public boolean isBlocked(ClientIdType clientId) {
        return clientBlockRegistry.isBlocked(clientId);
    }

    @Override
    public void block(ClientIdType clientId) {
        clientBlockRegistry.block(clientId);
        rateTracker.reset(clientId);
    }

    @Override
    public Class<ClientIdType> getClientIdType() {
        return clientBlockRegistry.getClientIdType();
    }
}
