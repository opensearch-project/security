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
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.tools.Hasher;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX;

/**
 * This class updates the security related configuration, as needed.
 */
public class SecuritySettingsConfigurer {

    static final List<String> REST_ENABLED_ROLES = List.of("all_access", "security_rest_api_access");
    static final List<String> SYSTEM_INDICES = List.of(
        ".plugins-ml-config",
        ".plugins-ml-connector",
        ".plugins-ml-model-group",
        ".plugins-ml-model",
        ".plugins-ml-task",
        ".plugins-ml-conversation-meta",
        ".plugins-ml-conversation-interactions",
        ".opendistro-alerting-config",
        ".opendistro-alerting-alert*",
        ".opendistro-anomaly-results*",
        ".opendistro-anomaly-detector*",
        ".opendistro-anomaly-checkpoints",
        ".opendistro-anomaly-detection-state",
        ".opendistro-reports-*",
        ".opensearch-notifications-*",
        ".opensearch-notebooks",
        ".opensearch-observability",
        ".ql-datasources",
        ".opendistro-asynchronous-search-response*",
        ".replication-metadata-store",
        ".opensearch-knn-models",
        ".geospatial-ip2geo-data*",
        ".plugins-flow-framework-config",
        ".plugins-flow-framework-templates",
        ".plugins-flow-framework-state"
    );
    static String ADMIN_PASSWORD = "";
    static String ADMIN_USERNAME = "admin";

    private final Installer installer;

    public SecuritySettingsConfigurer(Installer installer) {
        this.installer = installer;
    }

    /**
     * Configures security related changes to the opensearch configuration
     * 1. Checks if plugins is already configuration. If yes, exit
     * 2. Sets the custom admin password (Generates one if none is provided)
     * 3. Write the security config to opensearch.yml
     */
    public void configureSecuritySettings() {
        checkIfSecurityPluginIsAlreadyConfigured();
        updateAdminPassword();
        writeSecurityConfigToOpenSearchYML();
    }

    /**
     * Checks if security plugin is already configured. If so, the script execution will exit.
     */
    void checkIfSecurityPluginIsAlreadyConfigured() {
        // Check if the configuration file contains the 'plugins.security' string
        if (installer.OPENSEARCH_CONF_FILE != null && new File(installer.OPENSEARCH_CONF_FILE).exists()) {
            try (BufferedReader br = new BufferedReader(new FileReader(installer.OPENSEARCH_CONF_FILE, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.toLowerCase().contains("plugins.security")) {
                        System.out.println(installer.OPENSEARCH_CONF_FILE + " seems to be already configured for Security. Quit.");
                        System.exit(installer.skip_updates);
                    }
                }
            } catch (IOException e) {
                System.err.println("Error reading configuration file.");
                System.exit(-1);
            }
        } else {
            System.err.println("OpenSearch configuration file does not exist. Quit.");
            System.exit(-1);
        }
    }

    /**
     * Replaces the admin password in internal_users.yml with the custom or generated password
     */
    void updateAdminPassword() {
        String INTERNAL_USERS_FILE_PATH = installer.OPENSEARCH_CONF_DIR + "opensearch-security" + File.separator + "internal_users.yml";
        boolean shouldValidatePassword = installer.environment.equals(ExecutionEnvironment.DEMO);
        try {
            final PasswordValidator passwordValidator = PasswordValidator.of(
                Settings.builder()
                    .put(SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, "(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}")
                    .put(SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, 8)
                    .build()
            );

            // Read custom password from environment variable
            String initialAdminPassword = System.getenv().get(ConfigConstants.OPENSEARCH_INITIAL_ADMIN_PASSWORD);
            if (!Strings.isNullOrEmpty(initialAdminPassword)) {
                ADMIN_PASSWORD = initialAdminPassword;
            }

            // If script execution environment is set to demo, validate custom password, else if set to test, skip validation
            if (shouldValidatePassword
                && !ADMIN_PASSWORD.isEmpty()
                && passwordValidator.validate(ADMIN_USERNAME, ADMIN_PASSWORD) != RequestContentValidator.ValidationError.NONE) {
                System.out.println("Password " + ADMIN_PASSWORD + " is weak. Please re-try with a stronger password.");
                System.exit(-1);
            }

            // if ADMIN_PASSWORD is still an empty string, it implies no custom password was provided. We exit the setup.
            if (Strings.isNullOrEmpty(ADMIN_PASSWORD)) {
                System.out.println(
                    "No custom admin password found. Please provide a password via the environment variable OPENSEARCH_INITIAL_ADMIN_PASSWORD."
                );
                System.exit(-1);
            }

            // Print an update to the logs
            System.out.println("Admin password set successfully.");

            writePasswordToInternalUsersFile(ADMIN_PASSWORD, INTERNAL_USERS_FILE_PATH);

        } catch (IOException e) {
            System.out.println("Exception updating the admin password : " + e.getMessage());
            System.exit(-1);
        }
    }

    /**
     * Generate password hash and update it in the internal_users.yml file
     * @param adminPassword the password to be hashed and updated
     * @param internalUsersFile the file path string to internal_users.yml file
     * @throws IOException while reading, writing to files
     */
    void writePasswordToInternalUsersFile(String adminPassword, String internalUsersFile) throws IOException {
        String hashedAdminPassword = Hasher.hash(adminPassword.toCharArray());

        if (hashedAdminPassword.isEmpty()) {
            System.out.println("Hash the admin password failure, see console for details");
            System.exit(-1);
        }

        Path tempFilePath = Paths.get(internalUsersFile + ".tmp");
        Path internalUsersPath = Paths.get(internalUsersFile);

        try (
            BufferedReader reader = new BufferedReader(new FileReader(internalUsersFile, StandardCharsets.UTF_8));
            BufferedWriter writer = new BufferedWriter(new FileWriter(tempFilePath.toFile(), StandardCharsets.UTF_8))
        ) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.matches(" *hash: *\"\\$2a\\$12\\$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG\"")) {
                    line = line.replace(
                        "\"$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG\"",
                        "\"" + hashedAdminPassword + "\""
                    );
                }
                writer.write(line + System.lineSeparator());
            }
        } catch (IOException e) {
            throw new IOException("Unable to update the internal users file with the hashed password.");
        }
        Files.move(tempFilePath, internalUsersPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
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
            Yaml yaml = new Yaml();
            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            String yamlString = yaml.dump(securityConfigAsMap);
            writer.write(yamlString);
            writer.write(configFooter);
        } catch (IOException e) {
            System.err.println("Exception writing security configuration to opensearch.yml : " + e.getMessage());
            System.exit(-1);
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
        configMap.put("plugins.security.ssl.transport.enforce_hostname_verification", false);
        configMap.put("plugins.security.ssl.http.enabled", true);
        configMap.put("plugins.security.ssl.http.pemcert_filepath", Certificates.NODE_CERT.getFileName());
        configMap.put("plugins.security.ssl.http.pemkey_filepath", Certificates.NODE_KEY.getFileName());
        configMap.put("plugins.security.ssl.http.pemtrustedcas_filepath", Certificates.ROOT_CA.getFileName());
        configMap.put("plugins.security.allow_unsafe_democertificates", true);

        if (installer.initsecurity) {
            configMap.put("plugins.security.allow_default_init_securityindex", true);
        }

        configMap.put("plugins.security.authcz.admin_dn", List.of("CN=kirk,OU=client,O=client,L=test,C=de"));

        configMap.put("plugins.security.audit.type", "internal_opensearch");
        configMap.put("plugins.security.enable_snapshot_restore_privilege", true);
        configMap.put("plugins.security.check_snapshot_restore_write_privileges", true);
        configMap.put("plugins.security.restapi.roles_enabled", REST_ENABLED_ROLES);

        configMap.put("plugins.security.system_indices.enabled", true);
        configMap.put("plugins.security.system_indices.indices", SYSTEM_INDICES);

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
        JsonNode node;
        try {
            node = DefaultObjectMapper.YAML_MAPPER.readTree(new File(filePath));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

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
