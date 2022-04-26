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

package org.opensearch.security.auth.limiting;

import java.net.InetAddress;
import java.nio.file.Path;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthFailureListener;
import org.opensearch.security.auth.blocking.ClientBlockRegistry;
import org.opensearch.security.user.AuthCredentials;

public class AddressBasedRateLimiter extends AbstractRateLimiter<InetAddress> implements AuthFailureListener, ClientBlockRegistry<InetAddress> {

    public AddressBasedRateLimiter(Settings settings, Path configPath) {
        super(settings, configPath, InetAddress.class);
    }

    @Override
    public void onAuthFailure(InetAddress remoteAddress, AuthCredentials authCredentials, Object request) {
        if (this.rateTracker.track(remoteAddress)) {
            block(remoteAddress);
        }
    }
}
