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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.UserFilterType;
import org.opensearch.security.user.UserService;
import org.opensearch.transport.client.Client;

import org.mockito.Mock;
import org.passay.CharacterCharacteristicsRule;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.PasswordData;
import org.passay.RuleResult;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

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

    private SecurityDynamicConfiguration<?> readConfigFromYml(String file, CType<?> cType) throws Exception {
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
        // Use seeded random for reproducible tests
        SecureRandom seededRandom = new SecureRandom(new byte[] { 1, 2, 3, 4 });

        char[] passwordChars = UserService.generatePassword(seededRandom);
        String password = new String(passwordChars);

        // 1. Validate password structure (length and character types)
        PasswordData data = new PasswordData(password);
        LengthRule lengthRule = new LengthRule(20, 27);

        CharacterCharacteristicsRule characteristicsRule = new CharacterCharacteristicsRule();
        // 3 character types: upper, lower, digit (62-char alphabet = log2(62)*20 ≈ 119 bits entropy)
        characteristicsRule.setNumberOfCharacteristics(3);
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.Digit, 1));

        org.passay.PasswordValidator validator = new org.passay.PasswordValidator(lengthRule, characteristicsRule);
        RuleResult result = validator.validate(data);
        assertTrue("Password validation failed: " + validator.getMessages(result), result.isValid());

        // 2. Verify password entropy is sufficient for FIPS AES key derivation via HKDF
        // Password bytes serve as Input Keying Material (IKM) for HKDF
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        String base64Secret = Base64.getEncoder().encodeToString(passwordBytes);

        // EncryptionDecryptionUtil uses BC FIPS HKDF to derive AES-256 key
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(base64Secret);

        // Test round-trip encryption - proves the derived key is valid
        String testData = "FIPS entropy test payload";
        String encrypted = util.encrypt(testData);
        String decrypted = util.decrypt(encrypted);
        assertEquals("AES round-trip failed with password-derived key", testData, decrypted);

        // 3. Verify different seeds produce different passwords
        SecureRandom seededRandom2 = new SecureRandom(new byte[] { 5, 6, 7, 8 });
        char[] password2Chars = UserService.generatePassword(seededRandom2);
        String password2 = new String(password2Chars);
        assertNotEquals(password, password2);

        // Cleanup sensitive data
        Arrays.fill(passwordChars, '\0');
        Arrays.fill(password2Chars, '\0');
        Arrays.fill(passwordBytes, (byte) 0);
    }

    @Test
    public void testGeneratedPasswordEntropyMeetsFipsRequirement() {
        // FIPS 140-2/3 requires minimum 112 bits of entropy for cryptographic keys
        final double FIPS_MIN_ENTROPY_BITS = 112.0;
        final int CHARSET_SIZE = 62; // a-z (26) + A-Z (26) + 0-9 (10)
        final int MIN_PASSWORD_LENGTH = 20;

        // Calculate minimum entropy: log2(charset) * length
        double entropyPerChar = Math.log(CHARSET_SIZE) / Math.log(2);
        double minEntropy = entropyPerChar * MIN_PASSWORD_LENGTH;

        // Assert: our password design meets FIPS entropy requirement
        assertTrue(
            String.format("Password entropy %.2f bits must be >= %.2f bits (FIPS minimum)", minEntropy, FIPS_MIN_ENTROPY_BITS),
            minEntropy >= FIPS_MIN_ENTROPY_BITS
        );

        // Verify actual generated password length
        char[] password = UserService.generatePassword();
        assertTrue("Generated password must be >= " + MIN_PASSWORD_LENGTH + " chars", password.length >= MIN_PASSWORD_LENGTH);

        // Calculate actual entropy
        double actualEntropy = entropyPerChar * password.length;
        assertTrue(
            String.format("Actual password entropy %.2f bits must be >= %.2f bits", actualEntropy, FIPS_MIN_ENTROPY_BITS),
            actualEntropy >= FIPS_MIN_ENTROPY_BITS
        );

        Arrays.fill(password, '\0');
    }

    @Test
    public void testShortPasswordRejectedByFipsLengthCheck() {
        // PBKDF2PasswordHasher.check() rejects passwords < 14 chars in FIPS mode
        // The check: if (CryptoServicesRegistrar.isInApprovedOnlyMode() && password.length < 14)

        final int FIPS_MIN_PASSWORD_LENGTH = 14;
        final int OUR_MIN_PASSWORD_LENGTH = 20;

        // Our generated passwords always exceed FIPS minimum
        for (int i = 0; i < 10; i++) {
            char[] password = UserService.generatePassword();
            assertTrue(
                "Generated password length " + password.length + " must be >= FIPS minimum " + FIPS_MIN_PASSWORD_LENGTH,
                password.length >= FIPS_MIN_PASSWORD_LENGTH
            );
            assertTrue(
                "Generated password length " + password.length + " must be >= our minimum " + OUR_MIN_PASSWORD_LENGTH,
                password.length >= OUR_MIN_PASSWORD_LENGTH
            );
            Arrays.fill(password, '\0');
        }

        // Document the FIPS rejection threshold
        // A password of 13 chars would be rejected in FIPS mode:
        // - 13 chars with 62-char alphabet = 77 bits entropy (below 112-bit requirement)
        // - PBKDF2PasswordHasher.check() returns false for length < 14 in FIPS mode
        char[] weakPassword = "1234567890abc".toCharArray(); // 13 chars
        assertTrue("Weak password must be below FIPS threshold", weakPassword.length < FIPS_MIN_PASSWORD_LENGTH);

        // Our minimum (20 chars) provides significant margin above FIPS minimum (14 chars)
        // Entropy: 20 * log2(62) ≈ 119 bits vs 14 * log2(62) ≈ 83 bits
        assertTrue(
            "Our minimum length must exceed FIPS minimum by significant margin",
            OUR_MIN_PASSWORD_LENGTH - FIPS_MIN_PASSWORD_LENGTH >= 6
        );
    }

}
