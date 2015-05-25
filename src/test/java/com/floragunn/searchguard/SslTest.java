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

import javax.net.ssl.SSLHandshakeException;

import org.apache.http.NoHttpResponseException;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.floragunn.searchguard.util.SecurityUtil;

public class SslTest extends AbstractScenarioTest {

    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    @Test
    public void testHttps() throws Exception {

        enableSSL = true;

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.jacksonm", "ceo")
                .put("searchguard.authentication.settingsdb.user.jacksonm", "secret")
                .put("searchguard.authentication.authorizer.impl",
                        "com.floragunn.searchguard.authorization.simple.SettingsBasedAuthorizator")
                        .put("searchguard.authentication.authorizer.cache.enable", "false")
                        .put("searchguard.authentication.authentication_backend.impl",
                                "com.floragunn.searchguard.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                                .put("searchguard.authentication.authentication_backend.cache.enable", "false")
                                .put("searchguard.ssl.transport.http.enabled", true)
                .put("searchguard.ssl.transport.http.enforce_clientauth", true)
                                .put("searchguard.ssl.transport.http.keystore_filepath", SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardKS.jks"))
                                .put("searchguard.ssl.transport.http.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        username = "jacksonm";
        password = "secret";

        searchOnlyAllowed(settings, false);
    }

    @Test
    public void testHttpsFailSSLv3() throws Exception {
        thrown.expect(SSLHandshakeException.class);

        enableSSL = true;
        enableSSLv3Only = true;

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.jacksonm", "ceo")
                .put("searchguard.authentication.settingsdb.user.jacksonm", "secret")
                .put("searchguard.authentication.authorizer.impl",
                        "com.floragunn.searchguard.authorization.simple.SettingsBasedAuthorizator")
                        .put("searchguard.authentication.authorizer.cache.enable", "false")
                        .put("searchguard.authentication.authentication_backend.impl",
                                "com.floragunn.searchguard.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                                .put("searchguard.authentication.authentication_backend.cache.enable", "false")
                                .put("searchguard.ssl.transport.http.enabled", true)
                .put("searchguard.ssl.transport.http.enforce_clientauth", true)
                                .put("searchguard.ssl.transport.http.keystore_filepath", SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardKS.jks"))
                                .put("searchguard.ssl.transport.http.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        username = "jacksonm";
        password = "secret";

        searchOnlyAllowed(settings, false);
    }

    @Test
    public void testHttpsFail() throws Exception {
        thrown.expect(NoHttpResponseException.class);

        enableSSL = false;

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.jacksonm", "ceo")
                .put("searchguard.authentication.settingsdb.user.jacksonm", "secret")
                .put("searchguard.authentication.authorizer.impl",
                        "com.floragunn.searchguard.authorization.simple.SettingsBasedAuthorizator")
                        .put("searchguard.authentication.authorizer.cache.enable", "false")
                        .put("searchguard.authentication.authentication_backend.impl",
                                "com.floragunn.searchguard.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                                .put("searchguard.authentication.authentication_backend.cache.enable", "false")
                                .put("searchguard.ssl.transport.http.enabled", true)
                .put("searchguard.ssl.transport.http.enforce_clientauth", true)
                                .put("searchguard.ssl.transport.http.keystore_filepath", SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardKS.jks"))
                                .put("searchguard.ssl.transport.http.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        username = "jacksonm";
        password = "secret";

        searchOnlyAllowed(settings, false);
    }

    @Test
    public void testNodeSSL() throws Exception {

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.jacksonm", "ceo")
                .put("searchguard.authentication.settingsdb.user.jacksonm", "secret")
                .put("searchguard.authentication.authorizer.impl",
                        "com.floragunn.searchguard.authorization.simple.SettingsBasedAuthorizator")
                        .put("searchguard.authentication.authorizer.cache.enable", "false")
                        .put("searchguard.authentication.authentication_backend.impl",
                                "com.floragunn.searchguard.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                                .put("searchguard.authentication.authentication_backend.cache.enable", "false")
                                .put("searchguard.ssl.transport.node.enabled", true)
                .put("searchguard.ssl.transport.node.enforce_clientauth", true)
                                .put("searchguard.ssl.transport.node.keystore_filepath", SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardKS.jks"))
                                .put("searchguard.ssl.transport.node.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks"))
                                .put("searchguard.ssl.transport.node.encforce_hostname_verification", false).build();

        username = "jacksonm";
        password = "secret";

        searchOnlyAllowed(settings, false);
    }

    @Test
    public void mutualSSLAuthentication() throws Exception {

        enableSSL = true;

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .put("searchguard.authentication.http_authenticator.impl",
                        "com.floragunn.searchguard.authentication.http.clientcert.HTTPSClientCertAuthenticator")
                        .putArray("searchguard.authentication.authorization.settingsdb.roles.localhost", "ceo")
                        .put("searchguard.authentication.authorizer.impl",
                                "com.floragunn.searchguard.authorization.simple.SettingsBasedAuthorizator")
                                .put("searchguard.authentication.authorizer.cache.enable", "false")
                                .put("searchguard.authentication.authentication_backend.impl",
                                        "com.floragunn.searchguard.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                                        .put("searchguard.authentication.authentication_backend.cache.enable", "false")
                                        .put("searchguard.ssl.transport.http.enabled", true)
                .put("searchguard.ssl.transport.http.enforce_clientauth", true)
                                        .put("searchguard.ssl.transport.http.keystore_filepath", SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardKS.jks"))
                                        .put("searchguard.ssl.transport.http.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        searchOnlyAllowed(settings, false);
    }
}
