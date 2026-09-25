/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.securityconf;

import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.security.action.apitokens.ApiTokenRepository;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.internal.InternalAuthenticationBackend;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.ConfigV7.AuthcDomain;
import org.opensearch.security.user.User;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;

public class DynamicConfigModelV7Tests {

    @Test
    public void testResolvesAuthenticationBackendSettings() {
        MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(DynamicConfigSecrets.SETTING_PREFIX + "ldap.bind_dn", "cn=admin,dc=example,dc=com");
        secureSettings.setString(DynamicConfigSecrets.SETTING_PREFIX + "ldap.password", "secret");
        ConfigV7 config = configWithPassword("${keystore:ldap.password}");

        try (DynamicConfigSecrets secrets = new DynamicConfigSecrets(Settings.builder().setSecureSettings(secureSettings).build())) {
            new DynamicConfigModelV7(
                config,
                Settings.EMPTY,
                null,
                mock(InternalAuthenticationBackend.class),
                mock(ClusterInfoHolder.class),
                mock(ApiTokenRepository.class),
                secrets
            );
        }

        assertThat(CapturingAuthenticationBackend.SETTINGS.get().get("bind_dn"), is("cn=admin,dc=example,dc=com"));
        assertThat(CapturingAuthenticationBackend.SETTINGS.get().get("password"), is("secret"));
    }

    @Test
    public void testRejectsMissingAuthenticationBackendSecret() {
        ConfigV7 config = configWithPassword("${keystore:ldap.password}");

        try (DynamicConfigSecrets secrets = new DynamicConfigSecrets(Settings.EMPTY)) {
            assertThrows(
                SettingsException.class,
                () -> new DynamicConfigModelV7(
                    config,
                    Settings.EMPTY,
                    null,
                    mock(InternalAuthenticationBackend.class),
                    mock(ClusterInfoHolder.class),
                    mock(ApiTokenRepository.class),
                    secrets
                )
            );
        }
    }

    private static ConfigV7 configWithPassword(String password) {
        ConfigV7 config = new ConfigV7();
        config.dynamic = new ConfigV7.Dynamic();
        AuthcDomain domain = new AuthcDomain();
        domain.authentication_backend.type = CapturingAuthenticationBackend.class.getName();
        domain.authentication_backend.config = Map.of("bind_dn", "${keystore:ldap.bind_dn}", "password", password);
        config.dynamic.authc.getDomains().put("ldap", domain);
        return config;
    }

    public static class CapturingAuthenticationBackend implements AuthenticationBackend {
        private static final AtomicReference<Settings> SETTINGS = new AtomicReference<>();

        public CapturingAuthenticationBackend(Settings settings, Path configPath) {
            SETTINGS.set(settings);
        }

        @Override
        public String getType() {
            return "capturing";
        }

        @Override
        public User authenticate(AuthenticationContext context) throws OpenSearchSecurityException {
            throw new UnsupportedOperationException();
        }
    }
}
