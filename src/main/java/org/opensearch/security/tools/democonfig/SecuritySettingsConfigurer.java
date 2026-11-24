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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.FipsMode;

import org.snakeyaml.engine.v2.api.Dump;
import org.snakeyaml.engine.v2.api.DumpSettings;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;
import org.snakeyaml.engine.v2.common.FlowStyle;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;

import static org.opensearch.security.DefaultObjectMapper.yamlMapper;
import static org.opensearch.security.tools.democonfig.Installer.certificateGenerator;

/**
 * This class updates the security related configuration, as needed.
 */
public class SecuritySettingsConfigurer {

    static final List<String> REST_ENABLED_ROLES = List.of("all_access", "security_rest_api_access");
    static final Integer DEFAULT_PASSWORD_MIN_LENGTH = 8;
    static final String SALT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    static String ADMIN_PASSWORD = "";
    static String ADMIN_USERNAME = "admin";

    private final Installer installer;
    private final PasswordHasher passwordHasher;
    /**
     * Classpath copy of {@code config/internal_users.yml}, the BCrypt demo users the plugin ships. It has no source file
     * under {@code src/main/resources}: {@code processResources} in build.gradle copies and renames the config file into
     * {@code build/resources/main/democonfig}, and from there into the plugin jar, so there is only one file to maintain.
     */
    static final String SHIPPED_DEMO_USERS_RESOURCE = "/democonfig/internal_users_bcrypt.yml";
    /**
     * The same demo users with PBKDF2 hashes, kept in {@code src/main/resources/democonfig}. The hashes are generated once
     * and checked in rather than at build time, which would need hashing code and a fixed salt in the build script.
     * testPbkdf2DemoUsersMatchTheShippedDemoUsers keeps the users in line with config/internal_users.yml.
     */
    static final String PBKDF2_DEMO_USERS_RESOURCE = "/democonfig/internal_users_pbkdf2.yml";
    static final String PBKDF2_DEMO_PASSWORD_SUFFIX = "@OpenSearch";

    public SecuritySettingsConfigurer(Installer installer) {
        this.installer = installer;
        String hashingAlgorithm = FipsMode.isEnabled() ? PasswordHasherFactory.PBKDF2 : PasswordHasherFactory.BCRYPT;
        this.passwordHasher = PasswordHasherFactory.createPasswordHasher(
            Settings.builder().put(PasswordHasherFactory.ALGORITHM.getKey(), hashingAlgorithm).build()
        );
    }

    /**
     * Configures security related changes to the opensearch configuration
     * 1. Checks if plugins is already configuration. If yes, exit
     * 2. Sets the custom admin password (Generates one if none is provided)
     * 3. Write the security config to opensearch.yml
     */
    public void configureSecuritySettings() throws IOException {
        checkIfSecurityPluginIsAlreadyConfigured();
        if (FipsMode.isEnabled()) {
            replaceShippedDemoUsersWithPbkdf2();
        }
        updateAdminPassword();
        writeSecurityConfigToOpenSearchYML();
    }

    /**
     * The shipped internal_users.yml holds BCrypt hashes, which a FIPS node can neither verify nor compute. If the file is
     * still the shipped one, it is replaced with the same demo users hashed with PBKDF2. A file that already holds those
     * PBKDF2 users, from an earlier run that stopped before the end, is left alone without a message. Any other file
     * belongs to the operator and is kept.
     */
    void replaceShippedDemoUsersWithPbkdf2() throws IOException {
        final Path internalUsersFile = Path.of(internalUsersFilePath());
        final JsonNode currentUsers = yamlMapper().readTree(internalUsersFile.toFile());
        final JsonNode shippedUsers;
        try (InputStream shipped = demoConfigResource(SHIPPED_DEMO_USERS_RESOURCE)) {
            shippedUsers = yamlMapper().readTree(shipped);
        }
        final JsonNode pbkdf2DemoUsers;
        try (InputStream pbkdf2Users = demoConfigResource(PBKDF2_DEMO_USERS_RESOURCE)) {
            pbkdf2DemoUsers = yamlMapper().readTree(pbkdf2Users);
        }
        if (pbkdf2DemoUsers.equals(currentUsers)) {
            return;
        }
        if (!shippedUsers.equals(currentUsers)) {
            System.out.println("FIPS mode: internal_users.yml differs from the shipped demo users, so it is kept as it is.");
            return;
        }
        try (InputStream pbkdf2Users = demoConfigResource(PBKDF2_DEMO_USERS_RESOURCE)) {
            Files.copy(pbkdf2Users, internalUsersFile, StandardCopyOption.REPLACE_EXISTING);
        }
        System.out.println(
            "FIPS mode: replaced the BCrypt demo users in internal_users.yml with PBKDF2 hashes. "
                + "The password of each demo user except admin is its user name followed by \""
                + PBKDF2_DEMO_PASSWORD_SUFFIX
                + "\", for example \"kibanaserver"
                + PBKDF2_DEMO_PASSWORD_SUFFIX
                + "\"."
        );
    }

    private static InputStream demoConfigResource(String name) throws IOException {
        final InputStream resource = SecuritySettingsConfigurer.class.getResourceAsStream(name);
        if (resource == null) {
            throw new IOException("Resource " + name + " is missing from the security plugin jar.");
        }
        return resource;
    }

    /**
     * FIPS-approved PBKDF2 needs at least 112 bits of key material, so FIPS mode raises the demo minimum.
     */
    static int minimumPasswordLength() {
        if (FipsMode.isEnabled()) {
            return PasswordValidator.FIPS_MIN_PASSWORD_LENGTH;
        }
        return DEFAULT_PASSWORD_MIN_LENGTH;
    }

    private String internalUsersFilePath() {
        return installer.OPENSEARCH_CONF_DIR + "opensearch-security" + File.separator + "internal_users.yml";
    }

    boolean isSecurityPluginIsConfiguredWithDemoCerts() {
        if (installer.OPENSEARCH_CONF_FILE == null || !new File(installer.OPENSEARCH_CONF_FILE).exists()) {
            return false;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(installer.OPENSEARCH_CONF_FILE, StandardCharsets.UTF_8))) {
            Load yaml = new Load(LoadSettings.builder().build());
            @SuppressWarnings("unchecked")
            Map<String, Object> yamlData = (Map<String, Object>) yaml.loadFromReader(br);
            if (yamlData == null) return false;

            String[] requiredSettings = {
                "plugins.security.ssl.transport.pemcert_filepath",
                "plugins.security.ssl.transport.pemkey_filepath",
                "plugins.security.ssl.transport.pemtrustedcas_filepath",
                "plugins.security.ssl.http.pemcert_filepath",
                "plugins.security.ssl.http.pemkey_filepath",
                "plugins.security.ssl.http.pemtrustedcas_filepath" };

            String[] expectedValues = { "esnode.pem", "esnode-key.pem", "root-ca.pem", "esnode.pem", "esnode-key.pem", "root-ca.pem" };

            for (int i = 0; i < requiredSettings.length; i++) {
                String value = getNestedValue(yamlData, requiredSettings[i]);
                if (!expectedValues[i].equals(value)) {
                    return false;
                }
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private String getNestedValue(Map<String, Object> yamlData, String key) {
        // Check for flattened key first
        if (yamlData.containsKey(key)) {
            Object value = yamlData.get(key);
            return value instanceof String ? (String) value : null;
        }

        // Check for nested structure
        String[] parts = key.split("\\.");
        Object current = yamlData;
        for (String part : parts) {
            if (current instanceof Map) {
                current = ((Map<String, Object>) current).get(part);
            } else {
                return null;
            }
        }
        return current instanceof String ? (String) current : null;
    }

    /**
     * Checks if security plugin is already configured. If so, the script execution will exit.
     */
    @SuppressWarnings("unchecked")
    void checkIfSecurityPluginIsAlreadyConfigured() {
        // Check if the configuration file contains security settings
        if (installer.OPENSEARCH_CONF_FILE != null && new File(installer.OPENSEARCH_CONF_FILE).exists()) {
            try (BufferedReader br = new BufferedReader(new FileReader(installer.OPENSEARCH_CONF_FILE, StandardCharsets.UTF_8))) {
                Load yaml = new Load(LoadSettings.builder().build());
                @SuppressWarnings("unchecked")
                Map<String, Object> yamlData = (Map<String, Object>) yaml.loadFromReader(br);
                if (yamlData != null) {
                    // Check for flat keys
                    for (String key : yamlData.keySet()) {
                        if (key.startsWith("plugins.security")) {
                            if (isSecurityPluginIsConfiguredWithDemoCerts()) {
                                certificateGenerator.createDemoCertificates();
                            }
                            System.out.println(installer.OPENSEARCH_CONF_FILE + " seems to be already configured for Security. Quit.");
                            installer.getExitHandler().exit(installer.skip_updates);
                        }
                    }
                    // Check for nested keys
                    if (yamlData.containsKey("plugins")) {
                        Map<String, Object> plugins = (Map<String, Object>) yamlData.get("plugins");
                        for (String key : plugins.keySet()) {
                            if (key.startsWith("security")) {
                                if (isSecurityPluginIsConfiguredWithDemoCerts()) {
                                    certificateGenerator.createDemoCertificates();
                                }
                                System.out.println(installer.OPENSEARCH_CONF_FILE + " seems to be already configured for Security. Quit.");
                                installer.getExitHandler().exit(installer.skip_updates);
                            }
                        }
                    }
                }
            } catch (IOException e) {
                System.err.println("Error reading configuration file.");
                installer.getExitHandler().exit(-1);
            }
        } else {
            System.err.println("OpenSearch configuration file does not exist. Quit.");
            installer.getExitHandler().exit(-1);
        }
    }

    /**
     * Replaces the admin password in internal_users.yml with the custom or generated password
     */
    void updateAdminPassword() throws IOException {
        String INTERNAL_USERS_FILE_PATH = internalUsersFilePath();
        boolean shouldValidatePassword = installer.environment.equals(ExecutionEnvironment.DEMO);

        // check if the password `admin` is present, if not skip updating admin password
        if (!isAdminPasswordSetToAdmin(INTERNAL_USERS_FILE_PATH)) {
            System.out.println("Admin password seems to be custom configured. Skipping update to admin password.");
            return;
        }

        try {
            // Demo-only rules. Not plugins.security.restapi.password_* from opensearch.yml —
            // this installer runs before those cluster settings are loaded.
            final PasswordValidator passwordValidator = PasswordValidator.of(
                Settings.builder()
                    .put(
                        ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX,
                        "(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}"
                    )
                    .put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, minimumPasswordLength())
                    .build()
            );

            // Read custom password from environment variable
            String initialAdminPassword = System.getenv().get(ConfigConstants.OPENSEARCH_INITIAL_ADMIN_PASSWORD);
            if (!Strings.isNullOrEmpty(initialAdminPassword)) {
                ADMIN_PASSWORD = initialAdminPassword;
            }

            // If script execution environment is set to demo, validate custom password, else if set to test, skip validation
            if (shouldValidatePassword && !ADMIN_PASSWORD.isEmpty()) {
                RequestContentValidator.ValidationError response = passwordValidator.validate(ADMIN_USERNAME, ADMIN_PASSWORD);
                if (!RequestContentValidator.ValidationError.NONE.equals(response)) {
                    System.out.println(
                        String.format(
                            "Password %s failed validation: \"%s\". Please re-try with a minimum %d character password and must contain at least one uppercase letter, one lowercase letter, one digit, and one special character that is strong. Password strength can be tested here: https://lowe.github.io/tryzxcvbn",
                            ADMIN_PASSWORD,
                            response.message(),
                            minimumPasswordLength()
                        )
                    );
                    installer.getExitHandler().exit(-1);
                }
            }

            // if ADMIN_PASSWORD is still an empty string, it implies no custom password was provided. We exit the setup.
            if (Strings.isNullOrEmpty(ADMIN_PASSWORD)) {
                System.out.println(
                    String.format(
                        "No custom admin password found. Please provide a password via the environment variable %s.",
                        ConfigConstants.OPENSEARCH_INITIAL_ADMIN_PASSWORD
                    )
                );
                installer.getExitHandler().exit(-1);
            }

            // Update the custom password in internal_users.yml file
            writePasswordToInternalUsersFile(ADMIN_PASSWORD, INTERNAL_USERS_FILE_PATH);

            System.out.println("Admin password set successfully.");

        } catch (IOException e) {
            System.out.println("Exception updating the admin password : " + e.getMessage());
            installer.getExitHandler().exit(-1);
        }
    }

    /**
     * Check if the password for admin user was already updated. (Possibly via a custom internal_users.yml)
     * @param internalUsersFile Path to internal_users.yml file
     * @return true if password was already updated, false otherwise
     * @throws IOException if there was an error while reading the file
     */
    private boolean isAdminPasswordSetToAdmin(String internalUsersFile) throws IOException {
        JsonNode internalUsers = yamlMapper().readTree(new FileInputStream(internalUsersFile));
        if (!internalUsers.has("admin")) return false;
        String hash = internalUsers.get("admin").get("hash").asString();
        try {
            return passwordHasher.check(passwordHasher.defaultAdminPassword().toCharArray(), hash);
        } catch (IllegalArgumentException e) {
            // The hash library rejects a hash of another algorithm, for example a BCrypt hash in a customized file under FIPS
            // mode. Its message contains the hash, so it is not printed.
            System.out.println(
                "The admin hash in internal_users.yml was not created with the configured password hashing algorithm, so it cannot be the default admin password."
            );
            return false;
        }
    }

    /**
     * Generate password hash and update it in the internal_users.yml file
     * @param adminPassword the password to be hashed and updated
     * @param internalUsersFile the file path string to internal_users.yml file
     * @throws IOException while reading, writing to files
     */
    void writePasswordToInternalUsersFile(String adminPassword, String internalUsersFile) throws IOException {
        String hashedAdminPassword = passwordHasher.hash(adminPassword.toCharArray());

        if (hashedAdminPassword.isEmpty()) {
            System.out.println("Failure while hashing the admin password, see console for details.");
            installer.getExitHandler().exit(-1);
        }

        try {
            var map = yamlMapper().readValue(new File(internalUsersFile), new TypeReference<Map<String, LinkedHashMap<String, Object>>>() {
            });
            var admin = map.get("admin");
            if (admin != null) {
                // Replace the password since the default password was found via the check: isAdminPasswordSetToAdmin(..)
                admin.put("hash", hashedAdminPassword);
            }

            // Write the updated map back to the internal_users.yml file
            yamlMapper().writeValue(new File(internalUsersFile), map);
        } catch (JacksonException e) {
            throw new IOException("Unable to update the internal users file with the hashed password.");
        }
    }

    /**
     * Update opensearch.yml with security configuration information
     */
    void writeSecurityConfigToOpenSearchYML() {
        String configHeader = System.lineSeparator()
            + System.lineSeparator()
            + "######## Start OpenSearch Security Demo Configuration ########"
            + System.lineSeparator()
            + "# WARNING: revise all the lines below before you go into production"
            + System.lineSeparator();
        String configFooter = "######## End OpenSearch Security Demo Configuration ########" + System.lineSeparator();

        Map<String, Object> securityConfigAsMap = buildSecurityConfigMap();

        try (FileWriter writer = new FileWriter(installer.OPENSEARCH_CONF_FILE, StandardCharsets.UTF_8, true)) {
            writer.write(configHeader);
            Dump yaml = new Dump(DumpSettings.builder().setDefaultFlowStyle(FlowStyle.BLOCK).build());
            String yamlString = yaml.dumpToString(securityConfigAsMap);
            writer.write(yamlString);
            writer.write(configFooter);
        } catch (IOException e) {
            System.err.println("Exception writing security configuration to opensearch.yml : " + e.getMessage());
            installer.getExitHandler().exit(-1);
        }
    }

    /**
     * Helper method to build security configuration to append to opensearch.yml
     * @return the configuration map to be written to opensearch.yml
     */
    Map<String, Object> buildSecurityConfigMap() {
        Map<String, Object> configMap = new LinkedHashMap<>();

        configMap.put("plugins.security.ssl.transport.pemcert_filepath", Certificates.NODE_CERT.getFileName());
        configMap.put("plugins.security.ssl.transport.pemkey_filepath", Certificates.NODE_KEY.getFileName());
        configMap.put("plugins.security.ssl.transport.pemtrustedcas_filepath", Certificates.ROOT_CA.getFileName());
        configMap.put("transport.ssl.enforce_hostname_verification", false);
        configMap.put("plugins.security.ssl.http.enabled", true);
        configMap.put("plugins.security.ssl.http.pemcert_filepath", Certificates.NODE_CERT.getFileName());
        configMap.put("plugins.security.ssl.http.pemkey_filepath", Certificates.NODE_KEY.getFileName());
        configMap.put("plugins.security.ssl.http.pemtrustedcas_filepath", Certificates.ROOT_CA.getFileName());
        configMap.put("plugins.security.allow_unsafe_democertificates", true);
        configMap.put(ConfigConstants.SECURITY_COMPLIANCE_SALT, generateRandomSalt());

        // validateFipsMode refuses to start a FIPS node that hashes passwords with anything but PBKDF2.
        if (FipsMode.isEnabled()) {
            configMap.put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2);
        }

        if (installer.initsecurity) {
            configMap.put("plugins.security.allow_default_init_securityindex", true);
        }

        configMap.put("plugins.security.authcz.admin_dn", List.of("CN=kirk,OU=client,O=client,L=test,C=de"));

        configMap.put("plugins.security.audit.type", "internal_opensearch");
        configMap.put("plugins.security.enable_snapshot_restore_privilege", true);
        configMap.put("plugins.security.check_snapshot_restore_write_privileges", true);
        configMap.put("plugins.security.restapi.roles_enabled", REST_ENABLED_ROLES);

        configMap.put("plugins.security.system_indices.enabled", true);

        if (!isNetworkHostAlreadyPresent(installer.OPENSEARCH_CONF_FILE)) {
            if (installer.cluster_mode) {
                configMap.put("network.host", "0.0.0.0");
                configMap.put("node.name", "smoketestnode");
                configMap.put("cluster.initial_cluster_manager_nodes", "smoketestnode");
            }
        }

        if (!isNodeMaxLocalStorageNodesAlreadyPresent(installer.OPENSEARCH_CONF_FILE)) {
            configMap.put("node.max_local_storage_nodes", 3);
        }

        return configMap;
    }

    static String generateRandomSalt() {
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i < 16; i++) {
            sb.append(SALT_CHARS.charAt(random.nextInt(SALT_CHARS.length())));
        }
        return sb.toString();
    }

    /**
     * Helper method to check if network.host config is present
     * @param filePath path to opensearch.yml
     * @return true is present, false otherwise
     */
    static boolean isNetworkHostAlreadyPresent(String filePath) {
        try {
            String searchString = "network.host";
            return isKeyPresentInYMLFile(filePath, searchString);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Helper method to check if node.max_local_storage_nodes config is present
     * @param filePath path to opensearch.yml
     * @return true if present, false otherwise
     */
    static boolean isNodeMaxLocalStorageNodesAlreadyPresent(String filePath) {
        try {
            String searchString = "node.max_local_storage_nodes";
            return isKeyPresentInYMLFile(filePath, searchString);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Checks if the given key is present in the yml file
     * @param filePath path to yml file in which given key should be searched
     * @param key the key to be searched for
     * @return true if the key is present, false otherwise
     * @throws IOException if there was exception reading the file
     */
    static boolean isKeyPresentInYMLFile(String filePath, String key) throws IOException {
        final JsonNode node = yamlMapper().readTree(new File(filePath));
        return node.has(key);
    }

    /**
     * Helper method to create security_admin_demo.(sh|bat)
     * @param securityAdminScriptPath path to original script
     * @param securityAdminDemoScriptPath path to security admin demo script
     * @throws IOException if there was error reading/writing the file
     */
    void createSecurityAdminDemoScript(String securityAdminScriptPath, String securityAdminDemoScriptPath) throws IOException {
        String[] securityAdminCommands = getSecurityAdminCommands(securityAdminScriptPath);

        // Write securityadmin_demo script
        FileWriter writer = new FileWriter(securityAdminDemoScriptPath, StandardCharsets.UTF_8);
        for (String command : securityAdminCommands) {
            writer.write(command + System.lineSeparator());
        }
        writer.close();
    }

    /**
     * Return the command to be added to securityadmin_demo script
     * @param securityAdminScriptPath the path to securityadmin.(sh|bat)
     * @return the command string
     */
    String[] getSecurityAdminCommands(String securityAdminScriptPath) {
        String securityAdminExecutionPath = securityAdminScriptPath
            + "\" -cd \""
            + installer.OPENSEARCH_CONF_DIR
            + "opensearch-security\" -icl -key \""
            + installer.OPENSEARCH_CONF_DIR
            + Certificates.ADMIN_CERT_KEY.getFileName()
            + "\" -cert \""
            + installer.OPENSEARCH_CONF_DIR
            + Certificates.ADMIN_CERT.getFileName()
            + "\" -cacert \""
            + installer.OPENSEARCH_CONF_DIR
            + Certificates.ROOT_CA.getFileName()
            + "\" -nhnv";

        if (installer.OS.toLowerCase().contains("win")) {
            return new String[] { "@echo off", "call \"" + securityAdminExecutionPath };
        }

        return new String[] { "#!/bin/bash", "sudo" + " \"" + securityAdminExecutionPath };
    }
}
