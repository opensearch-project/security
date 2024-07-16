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
import java.util.Optional;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.UserFilterType;
import org.opensearch.security.user.UserService;

import org.mockito.Mock;
import org.passay.CharacterCharacteristicsRule;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.PasswordData;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotEquals;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
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
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.BCRYPT).build();
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        userService = new UserService(clusterService, configurationRepository, passwordHasher, settings, client);
        config = readConfigFromYml(usersYmlFile, CType.INTERNALUSERS);
    }

    @Test
    public void testServiceUserTypeFilter() {

        userService.includeAccountsIfType(config, UserFilterType.SERVICE);
        assertThat(config.getCEntries().size(), is(SERVICE_ACCOUNTS_IN_SETTINGS));
        assertThat(true, is(config.getCEntries().containsKey(serviceAccountUsername)));
        assertThat(false, is(config.getCEntries().containsKey(internalAccountUsername)));

    }

    @Test
    public void testInternalUserTypeFilter() {
        userService.includeAccountsIfType(config, UserFilterType.INTERNAL);
        assertThat(config.getCEntries().size(), is(INTERNAL_ACCOUNTS_IN_SETTINGS));
        assertThat(false, is(config.getCEntries().containsKey(serviceAccountUsername)));
        assertThat(true, is(config.getCEntries().containsKey(internalAccountUsername)));

    }

    @Test
    public void testAnyUserTypeFilter() {
        userService.includeAccountsIfType(config, UserFilterType.ANY);
        assertThat(config.getCEntries().size(), is(INTERNAL_ACCOUNTS_IN_SETTINGS + SERVICE_ACCOUNTS_IN_SETTINGS));
        assertThat(true, is(config.getCEntries().containsKey(serviceAccountUsername)));
        assertThat(true, is(config.getCEntries().containsKey(internalAccountUsername)));
    }

    private SecurityDynamicConfiguration<?> readConfigFromYml(String file, CType cType) throws Exception {
        final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());
        final String TEST_RESOURCE_RELATIVE_PATH = "../../resources/test/";

        final String adjustedFilePath = TEST_RESOURCE_RELATIVE_PATH + file;
        JsonNode jsonNode = YAML.readTree(Files.readString(new File(adjustedFilePath).toPath(), StandardCharsets.UTF_8));
        int configVersion = 1;

        if (jsonNode.get("_meta") != null) {
            assertThat(cType.toLCString(), is(jsonNode.get("_meta").get("type").asText()));
            configVersion = jsonNode.get("_meta").get("config_version").asInt();
        }
        return SecurityDynamicConfiguration.fromNode(jsonNode, cType, configVersion, 0, 0);
    }

    @Test
    public void restrictedFromUsername() {
        assertThat(UserService.restrictedFromUsername("aaaa"), is(Optional.empty()));
        assertThat(
            UserService.restrictedFromUsername("aaaa:bbb"),
            is(Optional.of("A restricted character(s) was detected in the account name. Please remove: ':'"))
        );
    }

    @Test
    public void testGeneratedPasswordContents() {
        String password = UserService.generatePassword();
        PasswordData data = new PasswordData(password);

        LengthRule lengthRule = new LengthRule(8, 16);

        CharacterCharacteristicsRule characteristicsRule = new CharacterCharacteristicsRule();

        // Define M (3 in this case)
        characteristicsRule.setNumberOfCharacteristics(3);

        // Define elements of N (upper, lower, digit, symbol)
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.Digit, 1));
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.Special, 1));

        org.passay.PasswordValidator validator = new org.passay.PasswordValidator(lengthRule, characteristicsRule);
        validator.validate(data);

        String password2 = UserService.generatePassword();
        PasswordData data2 = new PasswordData(password2);
        assertNotEquals(password, password2);
        assertNotEquals(data, data2);
    }

}
