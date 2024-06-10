/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.security.setting;

import com.fasterxml.jackson.databind.JsonMappingException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.Version;
import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigHelper;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.opensearch.security.configuration.ConfigurationRepository.DEFAULT_CONFIG_VERSION;
import static org.opensearch.security.setting.DeprecatedSettings.checkForDeprecatedSetting;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@RunWith(MockitoJUnitRunner.class)
public class DeprecatedSettingsTest {

    @Mock
    private DeprecationLogger logger;

    private DeprecationLogger original;

    @Before
    public void before() {
        original = DeprecatedSettings.DEPRECATION_LOGGER;
        DeprecatedSettings.DEPRECATION_LOGGER = logger;
    }

    @After
    public void after() {
        DeprecatedSettings.DEPRECATION_LOGGER = original;
        verifyNoMoreInteractions(logger);
    }

    @Test
    public void testCheckForDeprecatedSettingNoLegacy() {
        final Settings settings = Settings.builder().put("properKey", "value").build();

        checkForDeprecatedSetting(settings, "legacyKey", "properKey");

        verifyNoInteractions(logger);
    }

    @Test
    public void testCheckForDeprecatedSettingFoundLegacy() {
        final Settings settings = Settings.builder().put("legacyKey", "value").build();

        checkForDeprecatedSetting(settings, "legacyKey", "properKey");

        verify(logger).deprecate(eq("legacyKey"), anyString(), any(), any());
    }

    @Test
    public void testForTransportEnabledDeprecationMessageOnYamlLoad() throws Exception {
        ConfigHelper.fromYamlString(
            "---\n"
                + "_meta:\n"
                + "  type: \"config\"\n"
                + "  config_version: 2\n"
                + "config:\n"
                + "  dynamic:\n"
                + "    authc:\n"
                + "      authentication_domain_kerb:\n"
                + "        http_enabled: false\n"
                + "        transport_enabled: false\n"
                + "        order: 3\n"
                + "        http_authenticator:\n"
                + "          challenge: true\n"
                + "          type: \"kerberos\"\n"
                + "          config: {}\n"
                + "        authentication_backend:\n"
                + "          type: \"noop\"\n"
                + "          config: {}\n"
                + "        description: \"Migrated from v6\"\n"
                + "    authz:\n"
                + "      roles_from_xxx:\n"
                + "        http_enabled: false\n"
                + "        transport_enabled: false\n"
                + "        authorization_backend:\n"
                + "          type: \"xxx\"\n"
                + "          config: {}\n"
                + "        description: \"Migrated from v6\"",
            CType.CONFIG,
            DEFAULT_CONFIG_VERSION,
            0,
            0
        );
        verify(logger).deprecate(
            "transport_enabled",
            "In OpenSearch "
                + Version.CURRENT
                + " the setting '{}' is deprecated, it should be removed from the relevant config file using the following location information: In AuthcDomain, using http_authenticator=HttpAuthenticator [challenge=true, type=null, config={}], authentication_backend=AuthcBackend [type=org.opensearch.security.auth.internal.InternalAuthenticationBackend, config={}]",
            "transport_enabled"
        );
        verify(logger).deprecate(
            "transport_enabled",
            "In OpenSearch "
                + Version.CURRENT
                + " the setting '{}' is deprecated, it should be removed from the relevant config file using the following location information: In AuthzDomain, using authorization_backend=AuthzBackend [type=noop, config={}]",
            "transport_enabled"
        );
    }

    @Test
    public void testForExceptionOnUnknownAuthcAuthzSettingsOnYamlLoad() throws Exception {
        try {
            ConfigHelper.fromYamlString(
                "---\n"
                    + "_meta:\n"
                    + "  type: \"config\"\n"
                    + "  config_version: 2\n"
                    + "config:\n"
                    + "  dynamic:\n"
                    + "    authc:\n"
                    + "      authentication_domain_kerb:\n"
                    + "        http_enabled: false\n"
                    + "        unknown_property: false\n"
                    + "        order: 3\n"
                    + "        http_authenticator:\n"
                    + "          challenge: true\n"
                    + "          type: \"kerberos\"\n"
                    + "          config: {}\n"
                    + "        authentication_backend:\n"
                    + "          type: \"noop\"\n"
                    + "          config: {}\n"
                    + "        description: \"Migrated from v6\"\n"
                    + "    authz:\n"
                    + "      roles_from_xxx:\n"
                    + "        http_enabled: false\n"
                    + "        unknown_property: false\n"
                    + "        authorization_backend:\n"
                    + "          type: \"xxx\"\n"
                    + "          config: {}\n"
                    + "        description: \"Migrated from v6\"",
                CType.CONFIG,
                DEFAULT_CONFIG_VERSION,
                0,
                0
            );
        } catch (JsonMappingException e) {
            verifyNoInteractions(logger);
        }
    }
}
