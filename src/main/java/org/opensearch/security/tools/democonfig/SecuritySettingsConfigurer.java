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

import org.opensearch.common.settings.Settings;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.tools.Hasher;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX;
import static org.opensearch.security.user.UserService.generatePassword;

/**
 * This class updates the security related configuration, as needed.
 */
public class SecuritySettingsConfigurer extends Installer {

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
     * Replaces the admin password in internal_users.yml with the custom or generated password
     */
    static void updateAdminPassword() {
        String ADMIN_PASSWORD = "";
        String initialAdminPassword = System.getenv("initialAdminPassword");
        String ADMIN_PASSWORD_FILE_PATH = OPENSEARCH_CONF_DIR + "initialAdminPassword.txt";
        String INTERNAL_USERS_FILE_PATH = OPENSEARCH_CONF_DIR + "opensearch-security" + File.separator + "internal_users.yml";
        boolean shouldValidatePassword = environment.equals(ExecutionEnvironment.DEMO);
        try {
            final PasswordValidator passwordValidator = PasswordValidator.of(
                Settings.builder()
                    .put(SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, "(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}")
                    .put(SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, 8)
                    .build()
            );

            // Read custom password
            if (initialAdminPassword != null && !initialAdminPassword.isEmpty()) {
                ADMIN_PASSWORD = initialAdminPassword;
            } else {
                File adminPasswordFile = new File(ADMIN_PASSWORD_FILE_PATH);
                if (adminPasswordFile.exists() && adminPasswordFile.length() > 0) {
                    try (BufferedReader br = new BufferedReader(new FileReader(ADMIN_PASSWORD_FILE_PATH, StandardCharsets.UTF_8))) {
                        ADMIN_PASSWORD = br.readLine();
                    } catch (IOException e) {
                        System.out.println("Error reading admin password from initialAdminPassword.txt.");
                        System.exit(-1);
                    }
                }
            }

            // If script execution environment is set to demo, validate custom password, else if set to test, skip validation
            if (shouldValidatePassword
                && !ADMIN_PASSWORD.isEmpty()
                && passwordValidator.validate("admin", ADMIN_PASSWORD) != RequestContentValidator.ValidationError.NONE) {
                System.out.println("Password " + ADMIN_PASSWORD + " is weak. Please re-try with a stronger password.");
                System.exit(-1);
            }

            // if ADMIN_PASSWORD is still an empty string, it implies no custom password was provided. We proceed with generating a new one.
            if (ADMIN_PASSWORD.isEmpty()) {
                System.out.println("No custom admin password found. Generating a new password now.");
                // generate a new random password
                // We always validate a generated password
                while (passwordValidator.validate("admin", ADMIN_PASSWORD) != RequestContentValidator.ValidationError.NONE) {
                    ADMIN_PASSWORD = generatePassword();
                }
            }

            // print the password to the logs
            System.out.println("\t***************************************************");
            System.out.println("\t\tADMIN PASSWORD SET TO: " + ADMIN_PASSWORD);
            System.out.println("\t***************************************************");

            writePasswordToInternalUsersFile(ADMIN_PASSWORD, INTERNAL_USERS_FILE_PATH);

        } catch (IOException e) {
            System.out.println("Exception: " + e.getMessage());
            System.exit(-1);
        }
    }

    /**
     * Generate password hash and update it in the internal_users.yml file
     * @param adminPassword the password to be hashed and updated
     * @param internalUsersFile the file path string to internal_users.yml file
     * @throws IOException while reading, writing to files
     */
    static void writePasswordToInternalUsersFile(String adminPassword, String internalUsersFile) throws IOException {
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
     * Checks if security plugin is already configured. If so, the script execution will not continue.
     */
    static void checkIfSecurityPluginIsAlreadyConfigured() {
        // Check if the configuration file contains the 'plugins.security' string
        if (OPENSEARCH_CONF_FILE != null && new File(OPENSEARCH_CONF_FILE).exists()) {
            try (BufferedReader br = new BufferedReader(new FileReader(OPENSEARCH_CONF_FILE, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.toLowerCase().contains("plugins.security")) {
                        System.out.println(OPENSEARCH_CONF_FILE + " seems to be already configured for Security. Quit.");
                        System.exit(skip_updates);
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
     * Update opensearch.yml with security configuration information
     */
    static void writeSecurityConfigToOpenSearchYML() {
        String securityConfig = buildSecurityConfigString();

        try (FileWriter writer = new FileWriter(OPENSEARCH_CONF_FILE, StandardCharsets.UTF_8, true)) {
            writer.write(securityConfig);
        } catch (IOException e) {
            System.err.println("Exception writing security configuration to opensearch.yml.");
            System.exit(-1);
        }
    }

    /**
     * Helper method to build security configuration to append to opensearch.yml
     * @return the configuration string to be written to opensearch.yml
     */
    static String buildSecurityConfigString() {
        StringBuilder securityConfigLines = new StringBuilder();

        securityConfigLines.append("\n")
            .append("######## Start OpenSearch Security Demo Configuration ########\n")
            .append("# WARNING: revise all the lines below before you go into production\n")
            .append("plugins.security.ssl.transport.pemcert_filepath: esnode.pem\n")
            .append("plugins.security.ssl.transport.pemkey_filepath: esnode-key.pem\n")
            .append("plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem\n")
            .append("plugins.security.ssl.transport.enforce_hostname_verification: false\n")
            .append("plugins.security.ssl.http.enabled: true\n")
            .append("plugins.security.ssl.http.pemcert_filepath: esnode.pem\n")
            .append("plugins.security.ssl.http.pemkey_filepath: esnode-key.pem\n")
            .append("plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem\n")
            .append("plugins.security.allow_unsafe_democertificates: true\n");

        if (initsecurity) {
            securityConfigLines.append("plugins.security.allow_default_init_securityindex: true\n");
        }

        securityConfigLines.append("plugins.security.authcz.admin_dn:\n  - CN=kirk,OU=client,O=client,L=test, C=de\n\n");

        securityConfigLines.append("plugins.security.audit.type:  internal_opensearch\n");
        securityConfigLines.append("plugins.security.enable_snapshot_restore_privilege:  true\n");
        securityConfigLines.append("plugins.security.check_snapshot_restore_write_privileges:  true\n");
        securityConfigLines.append("plugins.security.restapi.roles_enabled:  [\"all_access\", \"security_rest_api_access\"]\n");

        securityConfigLines.append("plugins.security.system_indices.enabled: true\n" + "plugins.security.system_indices.indices: [")
            .append(SYSTEM_INDICES)
            .append("]\n");

        if (!isNetworkHostAlreadyPresent(OPENSEARCH_CONF_FILE)) {
            if (cluster_mode) {
                securityConfigLines.append("network.host: 0.0.0.0\n");
                securityConfigLines.append("node.name: smoketestnode\n");
                securityConfigLines.append("cluster.initial_cluster_manager_nodes: smoketestnode\n");
            }
        }

        if (!isNodeMaxLocalStorageNodesAlreadyPresent(OPENSEARCH_CONF_FILE)) {
            securityConfigLines.append("node.max_local_storage_nodes: 3\n");
        }

        securityConfigLines.append("######## End OpenSearch Security Demo Configuration ########\n");

        return securityConfigLines.toString();
    }

    /**
     * Helper method to check if network.host config is present
     * @param filePath path to opensearch.yml
     * @return true is present, false otherwise
     */
    static boolean isNetworkHostAlreadyPresent(String filePath) {
        try {
            String searchString = "^network.host";
            return isStringAlreadyPresentInFile(filePath, searchString);
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
            String searchString = "^node.max_local_storage_nodes";
            return isStringAlreadyPresentInFile(filePath, searchString);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Checks if given string is already present in the file
     * @param filePath path to file in which given string should be searched
     * @param searchString the string to be searched for
     * @return true if string is present, false otherwise
     * @throws IOException if there was exception reading the file
     */
    static boolean isStringAlreadyPresentInFile(String filePath, String searchString) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.matches(searchString)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Helper method to create security_admin_demo.(sh|bat)
     * @param securityAdminScriptPath path to original script
     * @param securityAdminDemoScriptPath path to security admin demo script
     * @throws IOException if there was error reading/writing the file
     */
    void createSecurityAdminDemoScript(String securityAdminScriptPath, String securityAdminDemoScriptPath) throws IOException {
        String[] securityAdminCommands;

        String securityAdminExecutionPath = securityAdminScriptPath
            + "\" -cd \""
            + OPENSEARCH_CONF_DIR
            + "opensearch-security\" -icl -key \""
            + OPENSEARCH_CONF_DIR
            + Certificates.ADMIN_CERT_KEY.getFileName()
            + "\" -cert \""
            + OPENSEARCH_CONF_DIR
            + Certificates.ADMIN_CERT.getFileName()
            + "\" -cacert \""
            + OPENSEARCH_CONF_DIR
            + Certificates.ROOT_CA.getFileName()
            + "\" -nhnv";

        if (OS.toLowerCase().contains("win")) {
            securityAdminCommands = new String[] { "@echo off", "call \"" + securityAdminExecutionPath };
        } else {
            securityAdminCommands = new String[] { "#!/bin/bash", "sudo" + " \"" + securityAdminExecutionPath };
        }

        // Write securityadmin_demo script
        FileWriter writer = new FileWriter(securityAdminDemoScriptPath, StandardCharsets.UTF_8);
        for (String command : securityAdminCommands) {
            writer.write(command + "\n");
        }
        writer.close();
    }
}
