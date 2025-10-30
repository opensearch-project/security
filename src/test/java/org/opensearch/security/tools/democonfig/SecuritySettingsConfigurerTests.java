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

package org.opensearch.security.tools.democonfig;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.junit.runner.RunWith;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.tools.Hasher;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.dlic.rest.validation.RequestContentValidator.ValidationError.INVALID_PASSWORD_INVALID_REGEX;
import static org.opensearch.security.dlic.rest.validation.RequestContentValidator.ValidationError.INVALID_PASSWORD_TOO_SHORT;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.DEFAULT_ADMIN_PASSWORD;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.DEFAULT_PASSWORD_MIN_LENGTH;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.REST_ENABLED_ROLES;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.SYSTEM_INDICES;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.isKeyPresentInYMLFile;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createDirectory;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createFile;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.deleteDirectoryRecursive;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

@RunWith(RandomizedRunner.class)
public class SecuritySettingsConfigurerTests {

    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;
    private final InputStream originalIn = System.in;

    private final String adminPasswordKey = ConfigConstants.OPENSEARCH_INITIAL_ADMIN_PASSWORD;

    private static final String PASSWORD_VALIDATION_FAILURE_MESSAGE =
        "Password %s failed validation: \"%s\". Please re-try with a minimum %d character password and must contain at least one uppercase letter, one lowercase letter, one digit, and one special character that is strong. Password strength can be tested here: https://lowe.github.io/tryzxcvbn";

    private static SecuritySettingsConfigurer securitySettingsConfigurer;
    private static Installer installer;

    // Custom exception thrown by the test exit handler
    public static class TestExitException extends RuntimeException {
        private final int status;

        public TestExitException(int status) {
            super("Exit code " + status);
            this.status = status;
        }

        public int getStatus() {
            return status;
        }
    }

    @Before
    public void setUp() throws IOException {
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(outContent));
        installer = Installer.getInstance();
        installer.buildOptions();
        securitySettingsConfigurer = new SecuritySettingsConfigurer(installer);
        setUpConf();
        setUpInternalUsersYML();
    }

    @After
    public void tearDown() throws NoSuchFieldException, IllegalAccessException {
        outContent.reset();
        System.setOut(originalOut);
        System.setErr(originalErr);
        System.setIn(originalIn);
        deleteDirectoryRecursive(installer.OPENSEARCH_CONF_DIR);
        unsetEnvVariables();
        Installer.resetInstance();
    }

    @Test
    public void testUpdateAdminPasswordWithCustomPassword() throws NoSuchFieldException, IllegalAccessException, IOException {
        String customPassword = "myStrongPassword123";
        setEnv(adminPasswordKey, customPassword);

        securitySettingsConfigurer.updateAdminPassword();

        assertThat(customPassword, equalTo(SecuritySettingsConfigurer.ADMIN_PASSWORD));
        verifyStdOutContainsString("Admin password set successfully.");
    }

    @Test
    public void testUpdateAdminPassword_noPasswordSupplied() throws IOException {
        // Ensure ADMIN_PASSWORD is empty so that no custom password is supplied
        SecuritySettingsConfigurer.ADMIN_PASSWORD = "";
        installer.setExitHandler(status -> { throw new TestExitException(status); });
        TestExitException ex = assertThrows(TestExitException.class, () -> securitySettingsConfigurer.updateAdminPassword());
        assertThat(ex.getStatus(), equalTo(-1));

        verifyStdOutContainsString(
            String.format(
                "No custom admin password found. Please provide a password via the environment variable %s.",
                ConfigConstants.OPENSEARCH_INITIAL_ADMIN_PASSWORD
            )
        );
    }

    @Test
    public void testUpdateAdminPasswordWithWeakPassword() throws NoSuchFieldException, IllegalAccessException {
        setEnv(adminPasswordKey, "weakpassword");
        installer.setExitHandler(status -> { throw new TestExitException(status); });
        TestExitException ex = assertThrows(TestExitException.class, () -> securitySettingsConfigurer.updateAdminPassword());
        assertThat(ex.getStatus(), equalTo(-1));

        verifyStdOutContainsString(
            String.format(
                PASSWORD_VALIDATION_FAILURE_MESSAGE,
                "weakpassword",
                INVALID_PASSWORD_INVALID_REGEX.message(),
                DEFAULT_PASSWORD_MIN_LENGTH
            )
        );
    }

    @Test
    public void testUpdateAdminPasswordWithShortPassword() throws NoSuchFieldException, IllegalAccessException {
        setEnv(adminPasswordKey, "short");
        installer.setExitHandler(status -> { throw new TestExitException(status); });
        TestExitException ex = assertThrows(TestExitException.class, () -> securitySettingsConfigurer.updateAdminPassword());
        assertThat(ex.getStatus(), equalTo(-1));
        verifyStdOutContainsString(
            String.format(PASSWORD_VALIDATION_FAILURE_MESSAGE, "short", INVALID_PASSWORD_TOO_SHORT.message(), DEFAULT_PASSWORD_MIN_LENGTH)
        );
    }

    @Test
    public void testUpdateAdminPasswordWithWeakPassword_skipPasswordValidation() throws NoSuchFieldException, IllegalAccessException,
        IOException {
        setEnv(adminPasswordKey, "weakpassword");
        installer.environment = ExecutionEnvironment.TEST;
        // In test environment, password validation is skipped.
        securitySettingsConfigurer.updateAdminPassword();

        assertThat("weakpassword", equalTo(SecuritySettingsConfigurer.ADMIN_PASSWORD));
        verifyStdOutContainsString("Admin password set successfully.");
    }

    @Test
    public void testUpdateAdminPasswordWithCustomInternalUsersYML() throws IOException {
        String internalUsersFile = installer.OPENSEARCH_CONF_DIR + "opensearch-security" + File.separator + "internal_users.yml";
        Path internalUsersFilePath = Paths.get(internalUsersFile);

        List<String> newContent = Arrays.asList(
            "_meta:",
            "  type: \"internalusers\"",
            "  config_version: 2",
            "admin:",
            "  hash: " + Hasher.hash(RandomStringUtils.randomAlphanumeric(16).toCharArray()),
            "  backend_roles:",
            "  - \"admin\""
        );
        // Overwrite existing content
        Files.write(internalUsersFilePath, newContent, StandardCharsets.UTF_8);

        securitySettingsConfigurer.updateAdminPassword();
        verifyStdOutContainsString("Admin password seems to be custom configured. Skipping update to admin password.");
    }

    @Test
    public void testUpdateAdminPasswordWithDefaultInternalUsersYml() {
        SecuritySettingsConfigurer.ADMIN_PASSWORD = "";
        installer.setExitHandler(status -> { throw new TestExitException(status); });
        TestExitException ex = assertThrows(TestExitException.class, () -> securitySettingsConfigurer.updateAdminPassword());
        assertThat(ex.getStatus(), equalTo(-1));

        verifyStdOutContainsString(
            String.format(
                "No custom admin password found. Please provide a password via the environment variable %s.",
                ConfigConstants.OPENSEARCH_INITIAL_ADMIN_PASSWORD
            )
        );
    }

    @Test
    public void testSecurityPluginAlreadyConfigured() {
        securitySettingsConfigurer.writeSecurityConfigToOpenSearchYML();
        String expectedMessage = installer.OPENSEARCH_CONF_FILE + " seems to be already configured for Security. Quit.";
        installer.setExitHandler(status -> { throw new TestExitException(status); });
        TestExitException ex = assertThrows(
            TestExitException.class,
            () -> securitySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured()
        );
        // Expecting exit code -1
        assertThat(ex.getStatus(), equalTo(-1));
        verifyStdOutContainsString(expectedMessage);
    }

    @Test
    public void testSecurityPluginNotConfigured() {
        // In case no security settings are in the configuration file the check method should complete without exiting.
        try {
            securitySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured();
        } catch (Exception e) {
            fail("Expected checkIfSecurityPluginIsAlreadyConfigured to succeed without any errors.");
        }
    }

    @Test
    public void testConfigFileDoesNotExist() {
        installer.OPENSEARCH_CONF_FILE = "path/to/nonexistentfile";
        String expectedMessage = "OpenSearch configuration file does not exist. Quit.";
        installer.setExitHandler(status -> { throw new TestExitException(status); });
        TestExitException ex = assertThrows(
            TestExitException.class,
            () -> securitySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured()
        );
        assertThat(ex.getStatus(), equalTo(-1));
        verifyStdOutContainsString(expectedMessage);
        // Reset the file pointer
        installer.OPENSEARCH_CONF_FILE = installer.OPENSEARCH_CONF_DIR + "opensearch.yml";
    }

    @Test
    public void testBuildSecurityConfigMap() {
        Map<String, Object> actual = securitySettingsConfigurer.buildSecurityConfigMap();

        assertThat(actual.size(), is(17));
        assertThat(actual.get("plugins.security.ssl.transport.pemcert_filepath"), equalTo(Certificates.NODE_CERT.getFileName()));
        assertThat(actual.get("plugins.security.ssl.transport.pemkey_filepath"), equalTo(Certificates.NODE_KEY.getFileName()));
        assertThat(actual.get("plugins.security.ssl.transport.pemtrustedcas_filepath"), equalTo(Certificates.ROOT_CA.getFileName()));
        assertThat(actual.get("transport.ssl.enforce_hostname_verification"), equalTo(false));
        assertThat(actual.get("plugins.security.ssl.http.enabled"), equalTo(true));
        assertThat(actual.get("plugins.security.ssl.http.pemcert_filepath"), equalTo(Certificates.NODE_CERT.getFileName()));
        assertThat(actual.get("plugins.security.ssl.http.pemkey_filepath"), equalTo(Certificates.NODE_KEY.getFileName()));
        assertThat(actual.get("plugins.security.ssl.http.pemtrustedcas_filepath"), equalTo(Certificates.ROOT_CA.getFileName()));
        assertThat(actual.get("plugins.security.allow_unsafe_democertificates"), equalTo(true));
        assertThat(actual.get("plugins.security.authcz.admin_dn"), equalTo(List.of("CN=kirk,OU=client,O=client,L=test,C=de")));
        assertThat(actual.get("plugins.security.audit.type"), equalTo("internal_opensearch"));
        assertThat(actual.get("plugins.security.enable_snapshot_restore_privilege"), equalTo(true));
        assertThat(actual.get("plugins.security.check_snapshot_restore_write_privileges"), equalTo(true));
        assertThat(actual.get("plugins.security.restapi.roles_enabled"), equalTo(REST_ENABLED_ROLES));
        assertThat(actual.get("plugins.security.system_indices.enabled"), equalTo(true));
        assertThat(actual.get("plugins.security.system_indices.indices"), equalTo(SYSTEM_INDICES));
        assertThat(actual.get("node.max_local_storage_nodes"), equalTo(3));

        installer.initsecurity = true;
        actual = securitySettingsConfigurer.buildSecurityConfigMap();
        assertThat(actual.get("plugins.security.allow_default_init_securityindex"), equalTo(true));

        installer.cluster_mode = true;
        actual = securitySettingsConfigurer.buildSecurityConfigMap();
        assertThat(actual.get("network.host"), equalTo("0.0.0.0"));
        assertThat(actual.get("node.name"), equalTo("smoketestnode"));
        assertThat(actual.get("cluster.initial_cluster_manager_nodes"), equalTo("smoketestnode"));
    }

    @Test
    public void testIsStringAlreadyPresentInFile_isNotPresent() throws IOException {
        String str1 = "network.host";
        String str2 = "some.random.config";

        installer.initsecurity = true;
        securitySettingsConfigurer.writeSecurityConfigToOpenSearchYML();

        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, str1), equalTo(false));
        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, str2), equalTo(false));
    }

    @Test
    public void testIsStringAlreadyPresentInFile_isPresent() throws IOException {
        String str1 = "network.host";
        String str2 = "some.random.config";

        installer.initsecurity = true;
        installer.cluster_mode = true;
        securitySettingsConfigurer.writeSecurityConfigToOpenSearchYML();

        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, str1), equalTo(true));
        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, str2), equalTo(false));
    }

    @Test
    public void testAssumeYesDoesNotInitializeClusterMode() throws IOException {
        String nodeName = "node.name"; // cluster_mode
        String securityIndex = "plugins.security.allow_default_init_securityindex"; // init_security

        installer.assumeyes = true;
        securitySettingsConfigurer.writeSecurityConfigToOpenSearchYML();

        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, nodeName), equalTo(false));
        assertThat(isKeyPresentInYMLFile(installer.OPENSEARCH_CONF_FILE, securityIndex), equalTo(false));
    }

    @Test
    public void testCreateSecurityAdminDemoScriptAndGetSecurityAdminCommands() throws IOException {
        String demoPath = installer.OPENSEARCH_CONF_DIR + "securityadmin_demo" + installer.FILE_EXTENSION;
        securitySettingsConfigurer.createSecurityAdminDemoScript("scriptPath", demoPath);

        assertThat(new File(demoPath).exists(), equalTo(true));

        String[] commands = securitySettingsConfigurer.getSecurityAdminCommands("scriptPath");

        try (BufferedReader reader = new BufferedReader(new FileReader(demoPath, StandardCharsets.UTF_8))) {
            assertThat(reader.readLine(), equalTo(commands[0]));
            assertThat(reader.readLine(), equalTo(commands[1]));
        }
    }

    @Test
    public void testCreateSecurityAdminDemoScript_invalidPath() {
        String demoPath = null;
        try {
            securitySettingsConfigurer.createSecurityAdminDemoScript("scriptPath", demoPath);
            fail("Expected to throw Exception");
        } catch (IOException | NullPointerException e) {
            // expected
        }
    }

    @Test
    public void testReadNonFlatYamlAlreadyConfigured() throws IOException {
        installer.OPENSEARCH_CONF_FILE = Paths.get("src/test/resources/opensearch-config-non-flat.yaml").toFile().getAbsolutePath();
        String expectedMessage = installer.OPENSEARCH_CONF_FILE + " seems to be already configured for Security. Quit.";
        installer.setExitHandler(status -> { throw new TestExitException(status); });
        TestExitException ex = assertThrows(
            TestExitException.class,
            () -> securitySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured()
        );
        assertThat(ex.getStatus(), equalTo(-1));
        verifyStdOutContainsString(expectedMessage);

        // Reset the configuration file pointer
        installer.OPENSEARCH_CONF_FILE = installer.OPENSEARCH_CONF_DIR + "opensearch.yml";
    }

    @SuppressWarnings("unchecked")
    public static void setEnv(String key, String value) throws NoSuchFieldException, IllegalAccessException {
        Class<?>[] classes = Collections.class.getDeclaredClasses();
        Map<String, String> env = System.getenv();
        for (Class<?> cl : classes) {
            if ("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
                Field field = cl.getDeclaredField("m");
                field.setAccessible(true);
                Object obj = field.get(env);
                Map<String, String> map = (Map<String, String>) obj;
                map.clear();
                map.put(key, value);
            }
        }
    }

    @SuppressWarnings("unchecked")
    public static void unsetEnvVariables() throws NoSuchFieldException, IllegalAccessException {
        Class<?>[] classes = Collections.class.getDeclaredClasses();
        Map<String, String> env = System.getenv();
        for (Class<?> cl : classes) {
            if ("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
                Field field = cl.getDeclaredField("m");
                field.setAccessible(true);
                Object obj = field.get(env);
                Map<String, String> map = (Map<String, String>) obj;
                map.clear();
            }
        }
    }

    void setUpConf() {
        installer.OPENSEARCH_CONF_DIR = System.getProperty("user.dir") + File.separator + "test-conf" + File.separator;
        installer.OPENSEARCH_CONF_FILE = installer.OPENSEARCH_CONF_DIR + "opensearch.yml";
        String securityConfDir = installer.OPENSEARCH_CONF_DIR + "opensearch-security" + File.separator;
        createDirectory(securityConfDir);
        createFile(securityConfDir + "internal_users.yml");
        createFile(installer.OPENSEARCH_CONF_FILE);
    }

    private void verifyStdOutContainsString(String s) {
        assertThat(outContent.toString(), containsString(s));
    }

    private void setUpInternalUsersYML() throws IOException {
        String internalUsersFile = installer.OPENSEARCH_CONF_DIR + "opensearch-security" + File.separator + "internal_users.yml";
        Path internalUsersFilePath = Paths.get(internalUsersFile);
        List<String> defaultContent = Arrays.asList(
            "_meta:",
            "  type: \"internalusers\"",
            "  config_version: 2",
            "admin:",
            "  hash: " + Hasher.hash(DEFAULT_ADMIN_PASSWORD.toCharArray()),
            "  reserved: true",
            "  backend_roles:",
            "  - \"admin\"",
            "  description: Demo admin user"
        );
        Files.write(internalUsersFilePath, defaultContent, StandardCharsets.UTF_8);
    }
}
