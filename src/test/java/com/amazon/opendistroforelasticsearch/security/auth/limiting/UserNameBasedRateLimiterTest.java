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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;

import org.opensearch.common.settings.Settings;
import org.junit.Test;

public class UserNameBasedRateLimiterTest {

    @Test
    public void simpleTest() throws Exception {
        Settings settings = Settings.builder().put("allowed_tries", 3).build();

        AddressBasedRateLimiter rateLimiter = new AddressBasedRateLimiter(settings, null);

        assertFalse(rateLimiter.isBlocked(InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 })));
        rateLimiter.onAuthFailure(InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 }), null, null);
        assertFalse(rateLimiter.isBlocked(InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 })));
        rateLimiter.onAuthFailure(InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 }), null, null);
        assertFalse(rateLimiter.isBlocked(InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 })));
        rateLimiter.onAuthFailure(InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 }), null, null);
        assertTrue(rateLimiter.isBlocked(InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 })));

    }
}
