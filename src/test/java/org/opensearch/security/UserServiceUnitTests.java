/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.hasher.BCryptPasswordHasher;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.user.UserFilterType;
import org.opensearch.security.user.UserService;

import org.mockito.Mock;

public class UserServiceUnitTests {
    SecurityDynamicConfiguration<?> config;
    @Mock
    ClusterService clusterService;
    @Mock
    ConfigurationRepository configurationRepository;
    @Mock
    Client client;
    UserService userService;

    final int SERVICE_ACCOUNTS_IN_SETTINGS = 1;
    final int INTERNAL_ACCOUNTS_IN_SETTINGS = 67;
    String serviceAccountUsername = "bug.99";
    String internalAccountUsername = "sarek";

    @Before
    public void setup() throws Exception {
        String usersYmlFile = "./internal_users.yml";
        Settings.Builder builder = Settings.builder();
        PasswordHasher passwordHasher = new BCryptPasswordHasher();
        userService = new UserService(clusterService, configurationRepository, passwordHasher, builder.build(), client);
        config = readConfigFromYml(usersYmlFile, CType.INTERNALUSERS);
    }

    @Test
    public void testServiceUserTypeFilter() {

        userService.includeAccountsIfType(config, UserFilterType.SERVICE);
        Assert.assertEquals(SERVICE_ACCOUNTS_IN_SETTINGS, config.getCEntries().size());
        Assert.assertEquals(config.getCEntries().containsKey(serviceAccountUsername), true);
        Assert.assertEquals(config.getCEntries().containsKey(internalAccountUsername), false);

    }

    @Test
    public void testInternalUserTypeFilter() {
        userService.includeAccountsIfType(config, UserFilterType.INTERNAL);
        Assert.assertEquals(INTERNAL_ACCOUNTS_IN_SETTINGS, config.getCEntries().size());
        Assert.assertEquals(config.getCEntries().containsKey(serviceAccountUsername), false);
        Assert.assertEquals(config.getCEntries().containsKey(internalAccountUsername), true);

    }

    @Test
    public void testAnyUserTypeFilter() {
        userService.includeAccountsIfType(config, UserFilterType.ANY);
        Assert.assertEquals(INTERNAL_ACCOUNTS_IN_SETTINGS + SERVICE_ACCOUNTS_IN_SETTINGS, config.getCEntries().size());
        Assert.assertEquals(config.getCEntries().containsKey(serviceAccountUsername), true);
        Assert.assertEquals(config.getCEntries().containsKey(internalAccountUsername), true);
    }

    private SecurityDynamicConfiguration<?> readConfigFromYml(String file, CType cType) throws Exception {
        final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());
        final String TEST_RESOURCE_RELATIVE_PATH = "../../resources/test/";

        final String adjustedFilePath = TEST_RESOURCE_RELATIVE_PATH + file;
        JsonNode jsonNode = YAML.readTree(Files.readString(new File(adjustedFilePath).toPath(), StandardCharsets.UTF_8));
        int configVersion = 1;

        if (jsonNode.get("_meta") != null) {
            Assert.assertEquals(jsonNode.get("_meta").get("type").asText(), cType.toLCString());
            configVersion = jsonNode.get("_meta").get("config_version").asInt();
        }
        return SecurityDynamicConfiguration.fromNode(jsonNode, cType, configVersion, 0, 0);
    }

}
