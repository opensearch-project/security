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
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.tools.democonfig.util.NoExitSecurityManager;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX;
import static org.opensearch.security.tools.democonfig.Installer.FILE_EXTENSION;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_CONF_DIR;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_CONF_FILE;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.getSecurityAdminCommands;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.isStringAlreadyPresentInFile;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.writeSecurityConfigToOpenSearchYML;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createDirectory;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createFile;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.deleteDirectoryRecursive;
import static org.opensearch.security.user.UserService.generatePassword;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
public class SecuritySettingsConfigurerTests {

    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final InputStream originalIn = System.in;

    private final String adminPasswordKey = "initialAdminPassword";

    @Before
    public void setUp() {
        System.setOut(new PrintStream(outContent));
        setUpConf();
    }

    @After
    public void tearDown() throws NoSuchFieldException, IllegalAccessException {
        System.setOut(originalOut);
        System.setIn(originalIn);
        deleteDirectoryRecursive(OPENSEARCH_CONF_DIR);
        Installer.environment = ExecutionEnvironment.DEMO;
        unsetEnv(adminPasswordKey);
    }

    @Test
    public void testUpdateAdminPasswordWithCustomPassword() throws NoSuchFieldException, IllegalAccessException {
        String customPassword = generateStrongPassword();
        setEnv(adminPasswordKey, customPassword);

        SecuritySettingsConfigurer.updateAdminPassword();

        assertThat(customPassword, is(equalTo(SecuritySettingsConfigurer.ADMIN_PASSWORD)));

        assertThat(outContent.toString(), containsString("ADMIN PASSWORD SET TO: " + customPassword));
    }

    @Test
    public void testUpdateAdminPasswordWithFilePassword() throws IOException {
        String customPassword = generateStrongPassword();
        String initialAdminPasswordTxt = System.getProperty("user.dir")
            + File.separator
            + "test-conf"
            + File.separator
            + adminPasswordKey
            + ".txt";
        createFile(initialAdminPasswordTxt);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(initialAdminPasswordTxt, StandardCharsets.UTF_8))) {
            writer.write(customPassword);
        } catch (IOException e) {
            throw new IOException("Unable to update the internal users file with the hashed password.");
        }

        SecuritySettingsConfigurer.updateAdminPassword();

        assertEquals(customPassword, SecuritySettingsConfigurer.ADMIN_PASSWORD);
        assertThat(outContent.toString(), containsString("ADMIN PASSWORD SET TO: " + customPassword));
    }

    @Test
    public void testUpdateAdminPasswordWithWeakPassword() throws NoSuchFieldException, IllegalAccessException {

        setEnv(adminPasswordKey, "weakpassword");
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            SecuritySettingsConfigurer.updateAdminPassword();

            assertThat(outContent.toString(), containsString("Password weakpassword is weak. Please re-try with a stronger password."));

        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testUpdateAdminPasswordWithWeakPassword_skipPasswordValidation() throws NoSuchFieldException, IllegalAccessException {
        setEnv(adminPasswordKey, "weakpassword");
        Installer.environment = ExecutionEnvironment.TEST;
        SecuritySettingsConfigurer.updateAdminPassword();

        assertThat("weakpassword", is(equalTo(SecuritySettingsConfigurer.ADMIN_PASSWORD)));
        assertThat(outContent.toString(), containsString("ADMIN PASSWORD SET TO: weakpassword"));
    }

    @Test
    public void testSecurityPluginAlreadyConfigured() {
        writeSecurityConfigToOpenSearchYML();
        try {
            System.setSecurityManager(new NoExitSecurityManager());
            String expectedMessage = OPENSEARCH_CONF_FILE + " seems to be already configured for Security. Quit.";

            SecuritySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured();
            assertThat(outContent.toString(), containsString(expectedMessage));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testSecurityPluginNotConfigured() {
        try {
            SecuritySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured();
        } catch (Exception e) {
            fail("Expected checkIfSecurityPluginIsAlreadyConfigured to succeed without any errors.");
        }
    }

    @Test
    public void testConfigFileDoesNotExist() {
        OPENSEARCH_CONF_FILE = "path/to/nonexistentfile";
        try {
            System.setSecurityManager(new NoExitSecurityManager());
            String expectedMessage = "OpenSearch configuration file does not exist. Quit.";

            SecuritySettingsConfigurer.checkIfSecurityPluginIsAlreadyConfigured();
            assertThat(outContent.toString(), containsString(expectedMessage));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
        // reset the file pointer
        OPENSEARCH_CONF_FILE = OPENSEARCH_CONF_DIR + "opensearch.yml";
    }

    @Test
    public void testBuildSecurityConfigString() {
        String actual = SecuritySettingsConfigurer.buildSecurityConfigString();

        String expected = System.lineSeparator()
            + "######## Start OpenSearch Security Demo Configuration ########"
            + System.lineSeparator()
            + "# WARNING: revise all the lines below before you go into production"
            + System.lineSeparator()
            + "plugins.security.ssl.transport.pemcert_filepath: esnode.pem"
            + System.lineSeparator()
            + "plugins.security.ssl.transport.pemkey_filepath: esnode-key.pem"
            + System.lineSeparator()
            + "plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem"
            + System.lineSeparator()
            + "plugins.security.ssl.transport.enforce_hostname_verification: false"
            + System.lineSeparator()
            + "plugins.security.ssl.http.enabled: true"
            + System.lineSeparator()
            + "plugins.security.ssl.http.pemcert_filepath: esnode.pem"
            + System.lineSeparator()
            + "plugins.security.ssl.http.pemkey_filepath: esnode-key.pem"
            + System.lineSeparator()
            + "plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem"
            + System.lineSeparator()
            + "plugins.security.allow_unsafe_democertificates: true"
            + System.lineSeparator()
            + "plugins.security.authcz.admin_dn:"
            + System.lineSeparator()
            + "  - CN=kirk,OU=client,O=client,L=test, C=de"
            + System.lineSeparator()
            + System.lineSeparator()
            + "plugins.security.audit.type:  internal_opensearch"
            + System.lineSeparator()
            + "plugins.security.enable_snapshot_restore_privilege:  true"
            + System.lineSeparator()
            + "plugins.security.check_snapshot_restore_write_privileges:  true"
            + System.lineSeparator()
            + "plugins.security.restapi.roles_enabled:  [\"all_access\", \"security_rest_api_access\"]"
            + System.lineSeparator()
            + "plugins.security.system_indices.enabled: true"
            + System.lineSeparator()
            + "plugins.security.system_indices.indices: [.plugins-ml-config, .plugins-ml-connector, .plugins-ml-model-group, .plugins-ml-model, .plugins-ml-task, .plugins-ml-conversation-meta, .plugins-ml-conversation-interactions, .opendistro-alerting-config, .opendistro-alerting-alert*, .opendistro-anomaly-results*, .opendistro-anomaly-detector*, .opendistro-anomaly-checkpoints, .opendistro-anomaly-detection-state, .opendistro-reports-*, .opensearch-notifications-*, .opensearch-notebooks, .opensearch-observability, .ql-datasources, .opendistro-asynchronous-search-response*, .replication-metadata-store, .opensearch-knn-models, .geospatial-ip2geo-data*]"
            + System.lineSeparator()
            + "node.max_local_storage_nodes: 3"
            + System.lineSeparator()
            + "######## End OpenSearch Security Demo Configuration ########"
            + System.lineSeparator();
        assertThat(actual, is(equalTo(expected)));

        Installer.initsecurity = true;
        actual = SecuritySettingsConfigurer.buildSecurityConfigString();
        assertThat(actual, containsString("plugins.security.allow_default_init_securityindex: true" + System.lineSeparator()));

        Installer.cluster_mode = true;
        actual = SecuritySettingsConfigurer.buildSecurityConfigString();
        assertThat(actual, containsString("network.host: 0.0.0.0" + System.lineSeparator()));
        assertThat(actual, containsString("node.name: smoketestnode" + System.lineSeparator()));
        assertThat(actual, containsString("cluster.initial_cluster_manager_nodes: smoketestnode" + System.lineSeparator()));
    }

    @Test
    public void testIsStringAlreadyPresentInFile() throws IOException {
        String str1 = "network.host";
        String str2 = "some.random.config";

        Installer.initsecurity = true;
        writeSecurityConfigToOpenSearchYML();

        assertThat(isStringAlreadyPresentInFile(OPENSEARCH_CONF_FILE, str1), is(equalTo(false)));
        assertThat(isStringAlreadyPresentInFile(OPENSEARCH_CONF_FILE, str2), is(equalTo(false)));

        Installer.cluster_mode = true;
        writeSecurityConfigToOpenSearchYML();

        assertThat(isStringAlreadyPresentInFile(OPENSEARCH_CONF_FILE, str1), is(equalTo(true)));
        assertThat(isStringAlreadyPresentInFile(OPENSEARCH_CONF_FILE, str2), is(equalTo(false)));
    }

    @Test
    public void testCreateSecurityAdminDemoScriptAndGetSecurityAdminCommands() throws IOException {
        String demoPath = OPENSEARCH_CONF_DIR + "securityadmin_demo" + FILE_EXTENSION;
        SecuritySettingsConfigurer.createSecurityAdminDemoScript("scriptPath", demoPath);

        assertThat(new File(demoPath).exists(), is(equalTo(true)));

        String[] commands = getSecurityAdminCommands("scriptPath");

        try (BufferedReader reader = new BufferedReader(new FileReader(demoPath, StandardCharsets.UTF_8))) {
            assertThat(reader.readLine(), is(commands[0]));
            assertThat(reader.readLine(), is(equalTo(commands[1])));
        }
    }

    @Test
    public void testCreateSecurityAdminDemoScript_invalidPath() {
        String demoPath = null;
        try {
            SecuritySettingsConfigurer.createSecurityAdminDemoScript("scriptPath", demoPath);
            fail("Expected to throw Exception");
        } catch (IOException | NullPointerException e) {
            // expected
        }
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
    public static void unsetEnv(String key) throws NoSuchFieldException, IllegalAccessException {
        Class<?>[] classes = Collections.class.getDeclaredClasses();
        Map<String, String> env = System.getenv();
        for (Class<?> cl : classes) {
            if ("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
                Field field = cl.getDeclaredField("m");
                field.setAccessible(true);
                Object obj = field.get(env);
                Map<String, String> map = (Map<String, String>) obj;
                map.remove(key);
            }
        }
    }

    void setUpConf() {
        OPENSEARCH_CONF_DIR = System.getProperty("user.dir") + File.separator + "test-conf" + File.separator;
        OPENSEARCH_CONF_FILE = OPENSEARCH_CONF_DIR + "opensearch.yml";
        String securityConfDir = OPENSEARCH_CONF_DIR + "opensearch-security" + File.separator;
        createDirectory(securityConfDir);
        createFile(securityConfDir + "internal_users.yml");
        createFile(OPENSEARCH_CONF_FILE);
    }

    private String generateStrongPassword() {
        String password = "";
        final PasswordValidator passwordValidator = PasswordValidator.of(
            Settings.builder()
                .put(SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, "(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}")
                .put(SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, 8)
                .build()
        );
        while (passwordValidator.validate("admin", password) != RequestContentValidator.ValidationError.NONE) {
            password = generatePassword();
        }
        return password;
    }
}
