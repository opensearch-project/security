/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard;

import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import waffle.mock.MockWindowsAuthProvider;

public class WindowsTest extends AbstractScenarioTest {

    @Test
    public void testSpnegoAuthWaffle() throws Exception {

        useSpnego = true;

        final Settings settings = ImmutableSettings
                .settingsBuilder()

                .put("searchguard.authentication.http_authenticator",
                        "com.floragunn.searchguard.authentication.http.waffle.HTTPWaffleAuthenticator")
                        .put("searchguard.authentication.spnego.login_config_filepath", System.getProperty("java.security.auth.login.config"))

                .put("searchguard.authentication.authorizer.cache.enable", "false")
                        .put("searchguard.authentication.authentication_backend",
                                "com.floragunn.searchguard.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                                .put("searchguard.authentication.authentication_backend.cache.enable", "false")
                                .put("searchguard.waffle.windows_auth_provider_impl", MockWindowsAuthProvider.class)

                .put("searchguard.authentication.authorizer", "com.floragunn.searchguard.authorization.waffle.WaffleAuthorizator")
                .put("searchguard.authentication.authentication_backend.cache.enable", "false").build();

        username = "Guest";
        password = "Guest";

        searchOnlyAllowed(settings, false);
    }

}
