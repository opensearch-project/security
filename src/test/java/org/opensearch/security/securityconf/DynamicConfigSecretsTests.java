/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.securityconf;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

public class DynamicConfigSecretsTests {

    @Test
    public void testResolvesExactKeystoreReference() {
        try (DynamicConfigSecrets secrets = new DynamicConfigSecrets(secureSettings("ldap.password", "secret"))) {
            Settings resolved = secrets.resolve(
                Settings.builder().put("password", "${keystore:ldap.password}").put("username", "plain-value").build()
            );

            assertThat(resolved.get("password"), is("secret"));
            assertThat(resolved.get("username"), is("plain-value"));
        }
    }

    @Test
    public void testDoesNotInterpolatePartialReference() {
        try (DynamicConfigSecrets secrets = new DynamicConfigSecrets(secureSettings("ldap.password", "secret"))) {
            Settings resolved = secrets.resolve(Settings.builder().put("password", "prefix-${keystore:ldap.password}").build());

            assertThat(resolved.get("password"), is("prefix-${keystore:ldap.password}"));
        }
    }

    @Test
    public void testMissingReferenceFailsValidation() {
        try (DynamicConfigSecrets secrets = new DynamicConfigSecrets(Settings.EMPTY)) {
            SettingsException exception = assertThrows(
                SettingsException.class,
                () -> secrets.validate(Settings.builder().put("password", "${keystore:ldap.password}").build())
            );

            assertThat(
                exception.getMessage(),
                is(
                    "Keystore setting [plugins.security.dynamic_config.secrets.ldap.password] referenced by dynamic configuration is missing"
                )
            );
        }
    }

    @Test
    public void testReloadRollsBackWhenRebuildFails() {
        try (DynamicConfigSecrets secrets = new DynamicConfigSecrets(secureSettings("ldap.password", "old-secret"))) {
            AtomicInteger rebuildCount = new AtomicInteger();

            assertThrows(IllegalStateException.class, () -> secrets.reload(secureSettings("ldap.password", "new-secret"), () -> {
                if (rebuildCount.incrementAndGet() == 1) {
                    assertResolvedPassword(secrets, "new-secret");
                    throw new IllegalStateException("rebuild failed");
                }
                assertResolvedPassword(secrets, "old-secret");
            }));

            assertThat(rebuildCount.get(), is(2));
            assertResolvedPassword(secrets, "old-secret");
        }
    }

    @Test
    public void testReloadReplacesSecrets() {
        try (DynamicConfigSecrets secrets = new DynamicConfigSecrets(secureSettings("ldap.password", "old-secret"))) {
            secrets.reload(secureSettings("ldap.password", "new-secret"), () -> assertResolvedPassword(secrets, "new-secret"));

            assertResolvedPassword(secrets, "new-secret");
        }
    }

    private static void assertResolvedPassword(DynamicConfigSecrets secrets, String expected) {
        Settings resolved = secrets.resolve(Settings.builder().put("password", "${keystore:ldap.password}").build());
        assertThat(resolved.get("password"), is(expected));
    }

    private static Settings secureSettings(String alias, String value) {
        MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(DynamicConfigSecrets.SETTING_PREFIX + alias, value);
        return Settings.builder().setSecureSettings(secureSettings).build();
    }
}
