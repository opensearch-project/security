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

package org.opensearch.security.tools;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX;
import static org.opensearch.security.user.UserService.generatePassword;

/**
 * This standalone class installs demo security configuration
 */
public final class InstallDemoConfiguration {
    private static boolean assumeyes = false;
    private static boolean initsecurity = false;
    private static boolean cluster_mode = false;
    private static boolean skip_updates = true;
    private static String SCRIPT_DIR;
    private static String BASE_DIR;
    private static String OPENSEARCH_CONF_FILE;
    private static String OPENSEARCH_BIN_DIR;
    private static String OPENSEARCH_PLUGINS_DIR;
    private static String OPENSEARCH_LIB_PATH;
    private static String OPENSEARCH_INSTALL_TYPE;
    private static String OPENSEARCH_CONF_DIR;
    private static String OPENSEARCH_VERSION;
    private static String SECURITY_VERSION;

    private static ExecutionEnvironment environment = ExecutionEnvironment.demo;

    private static final String OS = System.getProperty("os.name")
        + " "
        + System.getProperty("os.version")
        + " "
        + System.getProperty("os.arch");

    private static final String FILE_EXTENSION = OS.toLowerCase().contains("win") ? ".bat" : ".sh";

    private static final String SYSTEM_INDICES = ".plugins-ml-config, .plugins-ml-connector, .plugins-ml-model-group, .plugins-ml-model, "
        + ".plugins-ml-task, .plugins-ml-conversation-meta, .plugins-ml-conversation-interactions, .opendistro-alerting-config, .opendistro-alerting-alert*, "
        + ".opendistro-anomaly-results*, .opendistro-anomaly-detector*, .opendistro-anomaly-checkpoints, .opendistro-anomaly-detection-state, "
        + ".opendistro-reports-*, .opensearch-notifications-*, .opensearch-notebooks, .opensearch-observability, .ql-datasources, "
        + ".opendistro-asynchronous-search-response*, .replication-metadata-store, .opensearch-knn-models, .geospatial-ip2geo-data*";

    /**
     * Main method that coordinates the execution of various security-related tasks.
     *
     * @param options the options passed to the script
     */
    public static void main(String[] options) {
        printScriptHeaders();
        readOptions(options);
        gatherUserInputs();
        initializeVariables();
        printVariables();
        checkIfSecurityPluginIsAlreadyConfigured();
        setAdminPassword();
        createDemoCertificates();
        writeSecurityConfigToOpenSearchYML();
        finishScriptExecution();
    }

    /**
     * Prints deprecation warning and other headers for the scrip
     */
    private static void printScriptHeaders() {
        System.out.println("**************************************************************************");
        System.out.println("** This tool will be deprecated in the next major release of OpenSearch **");
        System.out.println("** https://github.com/opensearch-project/security/issues/1755           **");
        System.out.println("**************************************************************************");
        System.out.println("\n");
        System.out.println("OpenSearch Security Demo Installer");
        System.out.println("** Warning: Do not use on production or public reachable systems **");
    }

    /**
     * Reads the options passed to the script
     * @param options an array of strings containing options passed to the script
     */
    private static void readOptions(String[] options) {
        // set script execution dir
        SCRIPT_DIR = options[0];

        for (int i = 1; i < options.length; i++) {
            switch (options[i]) {
                case "-y":
                    assumeyes = true;
                    break;
                case "-i":
                    initsecurity = true;
                    break;
                case "-c":
                    cluster_mode = true;
                    break;
                case "-s":
                    skip_updates = false;
                    break;
                case "-t":
                    environment = ExecutionEnvironment.test;
                    break;
                case "-h":
                case "-?":
                    showHelp();
                    return;
                default:
                    System.out.println("Invalid option: " + options[i]);
            }
        }
    }

    /**
     * Prints the help menu when -h option is passed
     */
    private static void showHelp() {
        System.out.println("install_demo_configuration.sh [-y] [-i] [-c]");
        System.out.println("  -h show help");
        System.out.println("  -y confirm all installation dialogues automatically");
        System.out.println("  -i initialize Security plugin with default configuration (default is to ask if -y is not given)");
        System.out.println("  -c enable cluster mode by binding to all network interfaces (default is to ask if -y is not given)");
        System.out.println("  -s skip updates if config is already applied to opensearch.yml");
        System.out.println(
            "  -t set the execution environment to `test` to skip password validation. Should be used only for testing. (default is set to `demo`)"
        );
    }

    /**
     * Prompt the user and collect user inputs
     * Input collection will be skipped if -y option was passed
     */
    private static void gatherUserInputs() {
        if (!assumeyes) {
            try (Scanner scanner = new Scanner(System.in)) {

                if (!confirmAction(scanner, "Install demo certificates?")) {
                    System.exit(0);
                }

                if (!initsecurity) {
                    initsecurity = confirmAction(scanner, "Initialize Security Modules?");
                }

                if (!cluster_mode) {
                    System.out.println("Cluster mode requires maybe additional setup of:");
                    System.out.println("  - Virtual memory (vm.max_map_count)\n");
                    cluster_mode = confirmAction(scanner, "Enable cluster mode?");
                }
            }
        }
    }

    /**
     * Helper method to scan user inputs.
     * @param scanner object to be used for scanning user input
     * @param message prompt question
     * @return true or false based on user input
     */
    private static boolean confirmAction(Scanner scanner, String message) {
        System.out.print(message + " [y/N] ");
        String response = scanner.nextLine();
        return response.equalsIgnoreCase("yes") || response.equalsIgnoreCase("y");
    }

    /**
     * Initialize all class level variables required
     */
    private static void initializeVariables() {
        setBaseDir();
        setOpenSearchVariables();
        setSecurityVariables();
    }

    /**
     * Sets the base directory to be used by the script
     */
    private static void setBaseDir() {
        File baseDirFile = new File(SCRIPT_DIR).getParentFile().getParentFile().getParentFile();
        BASE_DIR = baseDirFile != null ? baseDirFile.getAbsolutePath() : null;

        if (BASE_DIR == null || !new File(BASE_DIR).isDirectory()) {
            System.out.println("DEBUG: basedir does not exist");
            System.exit(-1);
        }

        BASE_DIR += File.separator;
    }

    /**
     * Sets the variables for items at OpenSearch level
     */
    private static void setOpenSearchVariables() {
        OPENSEARCH_CONF_FILE = BASE_DIR + "config" + File.separator + "opensearch.yml";
        OPENSEARCH_BIN_DIR = BASE_DIR + "bin" + File.separator;
        OPENSEARCH_PLUGINS_DIR = BASE_DIR + "plugins" + File.separator;
        String OPENSEARCH_MODULES_DIR = BASE_DIR + "modules" + File.separator;
        OPENSEARCH_LIB_PATH = BASE_DIR + "lib" + File.separator;
        OPENSEARCH_INSTALL_TYPE = determineInstallType();

        if (!(new File(OPENSEARCH_CONF_FILE).exists())) {
            System.out.println("Unable to determine OpenSearch config directory. Quit.");
            System.exit(-1);
        }

        if (!(new File(OPENSEARCH_BIN_DIR).exists())) {
            System.out.println("Unable to determine OpenSearch bin directory. Quit.");
            System.exit(-1);
        }

        if (!(new File(OPENSEARCH_PLUGINS_DIR).exists())) {
            System.out.println("Unable to determine OpenSearch plugins directory. Quit.");
            System.exit(-1);
        }

        if (!(new File(OPENSEARCH_MODULES_DIR).exists())) {
            System.out.println("Unable to determine OpenSearch modules directory. Quit.");
            // System.exit(-1);
        }

        if (!(new File(OPENSEARCH_LIB_PATH).exists())) {
            System.out.println("Unable to determine OpenSearch lib directory. Quit.");
            System.exit(-1);
        }

        OPENSEARCH_CONF_DIR = new File(OPENSEARCH_CONF_FILE).getParent();
        OPENSEARCH_CONF_DIR = new File(OPENSEARCH_CONF_DIR).getAbsolutePath() + File.separator;
    }

    /**
     * Returns the installation type based on the underlying operating system
     * @return will be one of `.zip`, `.tar.gz` or `rpm/deb`
     */
    private static String determineInstallType() {
        // windows (.bat execution)
        if (OS.toLowerCase().contains("win")) {
            return ".zip";
        }

        // other OS (.sh execution)
        if (new File("/usr/share/opensearch").equals(new File(BASE_DIR))) {
            OPENSEARCH_CONF_FILE = "/usr/share/opensearch/config/opensearch.yml";
            if (!new File(OPENSEARCH_CONF_FILE).exists()) {
                OPENSEARCH_CONF_FILE = "/etc/opensearch/opensearch.yml";
            }
            return "rpm/deb";
        }
        return ".tar.gz";
    }

    /**
     * Sets the path variables for items at OpenSearch security plugin level
     */
    private static void setSecurityVariables() {
        if (!(new File(OPENSEARCH_PLUGINS_DIR + "opensearch-security").exists())) {
            System.out.println("OpenSearch Security plugin not installed. Quit.");
            System.exit(-1);
        }

        // Extract OpenSearch version and Security version
        File[] opensearchLibFiles = new File(OPENSEARCH_LIB_PATH).listFiles(
            pathname -> pathname.getName().startsWith("opensearch-") && pathname.getName().endsWith(".jar")
        );

        if (opensearchLibFiles != null && opensearchLibFiles.length > 0) {
            OPENSEARCH_VERSION = opensearchLibFiles[0].getName().replaceAll("opensearch-(.*).jar", "$1");
        }

        File[] securityFiles = new File(OPENSEARCH_PLUGINS_DIR + "opensearch-security").listFiles(
            pathname -> pathname.getName().startsWith("opensearch-security-") && pathname.getName().endsWith(".jar")
        );

        if (securityFiles != null && securityFiles.length > 0) {
            SECURITY_VERSION = securityFiles[0].getName().replaceAll("opensearch-security-(.*).jar", "$1");
        }

    }

    /**
     * Prints the initialized variables
     */
    private static void printVariables() {
        System.out.println("OpenSearch install type: " + OPENSEARCH_INSTALL_TYPE + " on " + OS);
        System.out.println("OpenSearch config dir: " + OPENSEARCH_CONF_DIR);
        System.out.println("OpenSearch config file: " + OPENSEARCH_CONF_FILE);
        System.out.println("OpenSearch bin dir: " + OPENSEARCH_BIN_DIR);
        System.out.println("OpenSearch plugins dir: " + OPENSEARCH_PLUGINS_DIR);
        System.out.println("OpenSearch lib dir: " + OPENSEARCH_LIB_PATH);
        System.out.println("Detected OpenSearch Version: " + OPENSEARCH_VERSION);
        System.out.println("Detected OpenSearch Security Version: " + SECURITY_VERSION);
    }

    /**
     * Checks if security plugin is already configured. If so, the script execution will not continue.
     */
    private static void checkIfSecurityPluginIsAlreadyConfigured() {
        // Check if the configuration file contains the 'plugins.security' string
        if (OPENSEARCH_CONF_FILE != null && new File(OPENSEARCH_CONF_FILE).exists()) {
            try (BufferedReader br = new BufferedReader(new FileReader(OPENSEARCH_CONF_FILE))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.toLowerCase().contains("plugins.security")) {
                        System.out.println(OPENSEARCH_CONF_FILE + " seems to be already configured for Security. Quit.");
                        System.exit(skip_updates ? 1 : 0);
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
    private static void setAdminPassword() {
        String ADMIN_PASSWORD = "";
        String initialAdminPassword = System.getenv("initialAdminPassword");
        String ADMIN_PASSWORD_FILE_PATH = OPENSEARCH_CONF_DIR + "initialAdminPassword.txt";
        String INTERNAL_USERS_FILE_PATH = OPENSEARCH_CONF_DIR + "opensearch-security" + File.separator + "internal_users.yml";
        boolean shouldValidatePassword = environment.equals(ExecutionEnvironment.demo);
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
                    try (BufferedReader br = new BufferedReader(new FileReader(ADMIN_PASSWORD_FILE_PATH))) {
                        ADMIN_PASSWORD = br.readLine();
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
    private static void writePasswordToInternalUsersFile(String adminPassword, String internalUsersFile) throws IOException {
        String hashedAdminPassword = Hasher.hash(adminPassword.toCharArray());

        if (hashedAdminPassword.isEmpty()) {
            System.out.println("Hash the admin password failure, see console for details");
            System.exit(-1);
        }

        Path tempFilePath = Paths.get(internalUsersFile + ".tmp");
        Path internalUsersPath = Paths.get(internalUsersFile);

        try (
            BufferedReader reader = new BufferedReader(new FileReader(internalUsersFile));
            BufferedWriter writer = new BufferedWriter(new FileWriter(tempFilePath.toFile()))
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
     * Creates demo super-admin, node and root certificates
     */
    public static void createDemoCertificates() {
        for (DemoCertificate cert : DemoCertificate.values()) {
            String filePath = OPENSEARCH_CONF_DIR + File.separator + cert.getFileName();
            try {
                FileWriter fileWriter = new FileWriter(filePath);
                fileWriter.write(cert.getContent());
                fileWriter.close();
            } catch (IOException e) {
                System.err.println("Error writing certificate file: " + cert.getFileName());
                System.exit(-1);
            }
        }
    }

    /**
     * Update opensearch.yml with security configuration information
     */
    private static void writeSecurityConfigToOpenSearchYML() {
        String securityConfig = buildSecurityConfigString();

        try (FileWriter writer = new FileWriter(OPENSEARCH_CONF_FILE, true)) {
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
    private static String buildSecurityConfigString() {
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
    private static boolean isNetworkHostAlreadyPresent(String filePath) {
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
    private static boolean isNodeMaxLocalStorageNodesAlreadyPresent(String filePath) {
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
    private static boolean isStringAlreadyPresentInFile(String filePath, String searchString) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
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
     * Prints end of script execution message and creates security admin demo file.
     */
    private static void finishScriptExecution() {
        System.out.println("### Success");
        System.out.println("### Execute this script now on all your nodes and then start all nodes");

        try {
            String securityAdminScriptPath = OPENSEARCH_PLUGINS_DIR
                + "opensearch-security"
                + File.separator
                + "tools"
                + File.separator
                + "securityadmin"
                + FILE_EXTENSION;
            String securityAdminDemoScriptPath = OPENSEARCH_CONF_DIR + "securityadmin_demo" + FILE_EXTENSION;

            createSecurityAdminDemoScript(securityAdminScriptPath, securityAdminDemoScriptPath);

            // Make securityadmin_demo script executable
            // not needed for windows
            if (!OS.toLowerCase().contains("win")) {
                Path file = Paths.get(securityAdminDemoScriptPath);
                Set<PosixFilePermission> perms = new HashSet<>();
                // Add the execute permission for owner, group, and others
                perms.add(PosixFilePermission.OWNER_READ);
                perms.add(PosixFilePermission.OWNER_EXECUTE);
                perms.add(PosixFilePermission.GROUP_EXECUTE);
                perms.add(PosixFilePermission.OTHERS_EXECUTE);
                Files.setPosixFilePermissions(file, perms);
            }

            // Read the last line of the security-admin script
            String lastLine = "";
            try (BufferedReader reader = new BufferedReader(new FileReader(securityAdminDemoScriptPath))) {
                String currentLine;
                while ((currentLine = reader.readLine()) != null) {
                    lastLine = currentLine;
                }
            }

            if (!initsecurity) {
                System.out.println("### After the whole cluster is up execute: ");
                System.out.println(lastLine);
                System.out.println("### or run ." + File.separator + "securityadmin_demo" + FILE_EXTENSION);
                System.out.println("### After that you can also use the Security Plugin ConfigurationGUI");
            } else {
                System.out.println("### OpenSearch Security will be automatically initialized.");
                System.out.println("### If you like to change the runtime configuration ");
                System.out.println(
                    "### change the files in .."
                        + File.separator
                        + ".."
                        + File.separator
                        + ".."
                        + File.separator
                        + "config"
                        + File.separator
                        + "opensearch-security and execute: "
                );
                System.out.println(lastLine);
                System.out.println("### or run ." + File.separator + "securityadmin_demo" + FILE_EXTENSION);
                System.out.println("### To use the Security Plugin ConfigurationGUI");
            }

            System.out.println("### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/admin.");
            System.out.println("### (Ignore the SSL certificate warning because we installed self-signed demo certificates)");

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * Helper method to create security_admin_demo.(sh|bat)
     * @param securityAdminScriptPath path to original script
     * @param securityAdminDemoScriptPath path to security admin demo script
     * @throws IOException if there was error reading/writing the file
     */
    private static void createSecurityAdminDemoScript(String securityAdminScriptPath, String securityAdminDemoScriptPath)
        throws IOException {
        String[] securityAdminCommands;

        String securityAdminExecutionPath = securityAdminScriptPath
            + "\" -cd \""
            + OPENSEARCH_CONF_DIR
            + "opensearch-security\" -icl -key \""
            + OPENSEARCH_CONF_DIR
            + DemoCertificate.ADMIN_CERT_KEY.getFileName()
            + "\" -cert \""
            + OPENSEARCH_CONF_DIR
            + DemoCertificate.ADMIN_CERT.getFileName()
            + "\" -cacert \""
            + OPENSEARCH_CONF_DIR
            + DemoCertificate.ROOT_CA.getFileName()
            + "\" -nhnv";

        if (OS.toLowerCase().contains("win")) {
            securityAdminCommands = new String[] { "@echo off", "call \"" + securityAdminExecutionPath };
        } else {
            securityAdminCommands = new String[] { "#!/bin/bash", "sudo" + " \"" + securityAdminExecutionPath };
        }

        // Write securityadmin_demo script
        FileWriter writer = new FileWriter(securityAdminDemoScriptPath);
        for (String command : securityAdminCommands) {
            writer.write(command + "\n");
        }
        writer.close();
    }
}

/**
 * Enum for demo certificates
 */
enum DemoCertificate {
    ADMIN_CERT(
        "kirk.pem",
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIEmDCCA4CgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iYwDQYJKoZIhvcNAQEL\n"
            + "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt\n"
            + "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl\n"
            + "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v\n"
            + "dCBDQTAeFw0yMzA4MjkyMDA2MzdaFw0zMzA4MjYyMDA2MzdaME0xCzAJBgNVBAYT\n"
            + "AmRlMQ0wCwYDVQQHDAR0ZXN0MQ8wDQYDVQQKDAZjbGllbnQxDzANBgNVBAsMBmNs\n"
            + "aWVudDENMAsGA1UEAwwEa2lyazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n"
            + "ggEBAJVcOAQlCiuB9emCljROAXnlsPbG7PE3kNz2sN+BbGuw686Wgyl3uToVHvVs\n"
            + "paMmLUqm1KYz9wMSWTIBZgpJ9hYaIbGxD4RBb7qTAJ8Q4ddCV2f7T4lxao/6ixI+\n"
            + "O0l/BG9E3mRGo/r0w+jtTQ3aR2p6eoxaOYbVyEMYtFI4QZTkcgGIPGxm05y8xonx\n"
            + "vV5pbSW9L7qAVDzQC8EYGQMMI4ccu0NcHKWtmTYJA/wDPE2JwhngHwbcIbc4cDz6\n"
            + "cG0S3FmgiKGuuSqUy35v/k3y7zMHQSdx7DSR2tzhH/bBL/9qGvpT71KKrxPtaxS0\n"
            + "bAqPcEkKWDo7IMlGGW7LaAWfGg8CAwEAAaOCASswggEnMAwGA1UdEwEB/wQCMAAw\n"
            + "DgYDVR0PAQH/BAQDAgXgMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMIHPBgNVHSME\n"
            + "gccwgcSAFBeH36Ba62YSp9XQ+LoSRTy3KwCcoYGVpIGSMIGPMRMwEQYKCZImiZPy\n"
            + "LGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQRXhh\n"
            + "bXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290IENB\n"
            + "MSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0GCFHfkrz782p+T9k0G\n"
            + "xGeM4+BrehWKMB0GA1UdDgQWBBSjMS8tgguX/V7KSGLoGg7K6XMzIDANBgkqhkiG\n"
            + "9w0BAQsFAAOCAQEANMwD1JYlwAh82yG1gU3WSdh/tb6gqaSzZK7R6I0L7slaXN9m\n"
            + "y2ErUljpTyaHrdiBFmPhU/2Kj2r+fIUXtXdDXzizx/JdmueT0nG9hOixLqzfoC9p\n"
            + "fAhZxM62RgtyZoaczQN82k1/geMSwRpEndFe3OH7arkS/HSbIFxQhAIy229eWe5d\n"
            + "1bUzP59iu7f3r567I4ob8Vy7PP+Ov35p7Vv4oDHHwgsdRzX6pvL6mmwVrQ3BfVec\n"
            + "h9Dqprr+ukYmjho76g6k5cQuRaB6MxqldzUg+2E7IHQP8MCF+co51uZq2nl33mtp\n"
            + "RGr6JbdHXc96zsLTL3saJQ8AWEfu1gbTVrwyRA==\n"
            + "-----END CERTIFICATE-----"
    ),
    ADMIN_CERT_KEY(
        "kirk-key.pem",
        "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVXDgEJQorgfXp\n"
            + "gpY0TgF55bD2xuzxN5Dc9rDfgWxrsOvOloMpd7k6FR71bKWjJi1KptSmM/cDElky\n"
            + "AWYKSfYWGiGxsQ+EQW+6kwCfEOHXQldn+0+JcWqP+osSPjtJfwRvRN5kRqP69MPo\n"
            + "7U0N2kdqenqMWjmG1chDGLRSOEGU5HIBiDxsZtOcvMaJ8b1eaW0lvS+6gFQ80AvB\n"
            + "GBkDDCOHHLtDXBylrZk2CQP8AzxNicIZ4B8G3CG3OHA8+nBtEtxZoIihrrkqlMt+\n"
            + "b/5N8u8zB0Encew0kdrc4R/2wS//ahr6U+9Siq8T7WsUtGwKj3BJClg6OyDJRhlu\n"
            + "y2gFnxoPAgMBAAECggEAP5TOycDkx+megAWVoHV2fmgvgZXkBrlzQwUG/VZQi7V4\n"
            + "ZGzBMBVltdqI38wc5MtbK3TCgHANnnKgor9iq02Z4wXDwytPIiti/ycV9CDRKvv0\n"
            + "TnD2hllQFjN/IUh5n4thHWbRTxmdM7cfcNgX3aZGkYbLBVVhOMtn4VwyYu/Mxy8j\n"
            + "xClZT2xKOHkxqwmWPmdDTbAeZIbSv7RkIGfrKuQyUGUaWhrPslvYzFkYZ0umaDgQ\n"
            + "OAthZew5Bz3OfUGOMPLH61SVPuJZh9zN1hTWOvT65WFWfsPd2yStI+WD/5PU1Doo\n"
            + "1RyeHJO7s3ug8JPbtNJmaJwHe9nXBb/HXFdqb976yQKBgQDNYhpu+MYSYupaYqjs\n"
            + "9YFmHQNKpNZqgZ4ceRFZ6cMJoqpI5dpEMqToFH7tpor72Lturct2U9nc2WR0HeEs\n"
            + "/6tiptyMPTFEiMFb1opQlXF2ae7LeJllntDGN0Q6vxKnQV+7VMcXA0Y8F7tvGDy3\n"
            + "qJu5lfvB1mNM2I6y/eMxjBuQhwKBgQC6K41DXMFro0UnoO879pOQYMydCErJRmjG\n"
            + "/tZSy3Wj4KA/QJsDSViwGfvdPuHZRaG9WtxdL6kn0w1exM9Rb0bBKl36lvi7o7xv\n"
            + "M+Lw9eyXMkww8/F5d7YYH77gIhGo+RITkKI3+5BxeBaUnrGvmHrpmpgRXWmINqr0\n"
            + "0jsnN3u0OQKBgCf45vIgItSjQb8zonLz2SpZjTFy4XQ7I92gxnq8X0Q5z3B+o7tQ\n"
            + "K/4rNwTju/sGFHyXAJlX+nfcK4vZ4OBUJjP+C8CTjEotX4yTNbo3S6zjMyGQqDI5\n"
            + "9aIOUY4pb+TzeUFJX7If5gR+DfGyQubvvtcg1K3GHu9u2l8FwLj87sRzAoGAflQF\n"
            + "RHuRiG+/AngTPnZAhc0Zq0kwLkpH2Rid6IrFZhGLy8AUL/O6aa0IGoaMDLpSWUJp\n"
            + "nBY2S57MSM11/MVslrEgGmYNnI4r1K25xlaqV6K6ztEJv6n69327MS4NG8L/gCU5\n"
            + "3pEm38hkUi8pVYU7in7rx4TCkrq94OkzWJYurAkCgYATQCL/rJLQAlJIGulp8s6h\n"
            + "mQGwy8vIqMjAdHGLrCS35sVYBXG13knS52LJHvbVee39AbD5/LlWvjJGlQMzCLrw\n"
            + "F7oILW5kXxhb8S73GWcuMbuQMFVHFONbZAZgn+C9FW4l7XyRdkrbR1MRZ2km8YMs\n"
            + "/AHmo368d4PSNRMMzLHw8Q==\n"
            + "-----END PRIVATE KEY-----"
    ),
    NODE_CERT(
        "esnode.pem",
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIEPDCCAySgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iIwDQYJKoZIhvcNAQEL\n"
            + "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt\n"
            + "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl\n"
            + "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v\n"
            + "dCBDQTAeFw0yMzA4MjkwNDIzMTJaFw0zMzA4MjYwNDIzMTJaMFcxCzAJBgNVBAYT\n"
            + "AmRlMQ0wCwYDVQQHDAR0ZXN0MQ0wCwYDVQQKDARub2RlMQ0wCwYDVQQLDARub2Rl\n"
            + "MRswGQYDVQQDDBJub2RlLTAuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA\n"
            + "A4IBDwAwggEKAoIBAQCm93kXteDQHMAvbUPNPW5pyRHKDD42XGWSgq0k1D29C/Ud\n"
            + "yL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0\n"
            + "HGkn47XVu3EwbfrTENg3jFu+Oem6a/501SzITzJWtS0cn2dIFOBimTVpT/4Zv5qr\n"
            + "XA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8n\n"
            + "dibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b6l+KLo3IKpfTbAIJXIO+M67FLtWKtttD\n"
            + "ao94B069skzKk6FPgW/OZh6PRCD0oxOavV+ld2SjAgMBAAGjgcYwgcMwRwYDVR0R\n"
            + "BEAwPogFKgMEBQWCEm5vZGUtMC5leGFtcGxlLmNvbYIJbG9jYWxob3N0hxAAAAAA\n"
            + "AAAAAAAAAAAAAAABhwR/AAABMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAUBggrBgEF\n"
            + "BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU0/qDQaY10jIo\n"
            + "wCjLUpz/HfQXyt8wHwYDVR0jBBgwFoAUF4ffoFrrZhKn1dD4uhJFPLcrAJwwDQYJ\n"
            + "KoZIhvcNAQELBQADggEBAD2hkndVih6TWxoe/oOW0i2Bq7ScNO/n7/yHWL04HJmR\n"
            + "MaHv/Xjc8zLFLgHuHaRvC02ikWIJyQf5xJt0Oqu2GVbqXH9PBGKuEP2kCsRRyU27\n"
            + "zTclAzfQhqmKBTYQ/3lJ3GhRQvXIdYTe+t4aq78TCawp1nSN+vdH/1geG6QjMn5N\n"
            + "1FU8tovDd4x8Ib/0dv8RJx+n9gytI8n/giIaDCEbfLLpe4EkV5e5UNpOnRgJjjuy\n"
            + "vtZutc81TQnzBtkS9XuulovDE0qI+jQrKkKu8xgGLhgH0zxnPkKtUg2I3Aq6zl1L\n"
            + "zYkEOUF8Y25J6WeY88Yfnc0iigI+Pnz5NK8R9GL7TYo=\n"
            + "-----END CERTIFICATE-----"
    ),
    NODE_KEY(
        "esnode-key.pem",
        "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCm93kXteDQHMAv\n"
            + "bUPNPW5pyRHKDD42XGWSgq0k1D29C/UdyL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0\n"
            + "o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0HGkn47XVu3EwbfrTENg3jFu+Oem6a/50\n"
            + "1SzITzJWtS0cn2dIFOBimTVpT/4Zv5qrXA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1\n"
            + "MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8ndibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b\n"
            + "6l+KLo3IKpfTbAIJXIO+M67FLtWKtttDao94B069skzKk6FPgW/OZh6PRCD0oxOa\n"
            + "vV+ld2SjAgMBAAECggEAQK1+uAOZeaSZggW2jQut+MaN4JHLi61RH2cFgU3COLgo\n"
            + "FIiNjFn8f2KKU3gpkt1It8PjlmprpYut4wHI7r6UQfuv7ZrmncRiPWHm9PB82+ZQ\n"
            + "5MXYqj4YUxoQJ62Cyz4sM6BobZDrjG6HHGTzuwiKvHHkbsEE9jQ4E5m7yfbVvM0O\n"
            + "zvwrSOM1tkZihKSTpR0j2+taji914tjBssbn12TMZQL5ItGnhR3luY8mEwT9MNkZ\n"
            + "xg0VcREoAH+pu9FE0vPUgLVzhJ3be7qZTTSRqv08bmW+y1plu80GbppePcgYhEow\n"
            + "dlW4l6XPJaHVSn1lSFHE6QAx6sqiAnBz0NoTPIaLyQKBgQDZqDOlhCRciMRicSXn\n"
            + "7yid9rhEmdMkySJHTVFOidFWwlBcp0fGxxn8UNSBcXdSy7GLlUtH41W9PWl8tp9U\n"
            + "hQiiXORxOJ7ZcB80uNKXF01hpPj2DpFPWyHFxpDkWiTAYpZl68rOlYujxZUjJIej\n"
            + "VvcykBC2BlEOG9uZv2kxcqLyJwKBgQDEYULTxaTuLIa17wU3nAhaainKB3vHxw9B\n"
            + "Ksy5p3ND43UNEKkQm7K/WENx0q47TA1mKD9i+BhaLod98mu0YZ+BCUNgWKcBHK8c\n"
            + "uXpauvM/pLhFLXZ2jvEJVpFY3J79FSRK8bwE9RgKfVKMMgEk4zOyZowS8WScOqiy\n"
            + "hnQn1vKTJQKBgElhYuAnl9a2qXcC7KOwRsJS3rcKIVxijzL4xzOyVShp5IwIPbOv\n"
            + "hnxBiBOH/JGmaNpFYBcBdvORE9JfA4KMQ2fx53agfzWRjoPI1/7mdUk5RFI4gRb/\n"
            + "A3jZRBoopgFSe6ArCbnyQxzYzToG48/Wzwp19ZxYrtUR4UyJct6f5n27AoGBAJDh\n"
            + "KIpQQDOvCdtjcbfrF4aM2DPCfaGPzENJriwxy6oEPzDaX8Bu/dqI5Ykt43i/zQrX\n"
            + "GpyLaHvv4+oZVTiI5UIvcVO9U8hQPyiz9f7F+fu0LHZs6f7hyhYXlbe3XFxeop3f\n"
            + "5dTKdWgXuTTRF2L9dABkA2deS9mutRKwezWBMQk5AoGBALPtX0FrT1zIosibmlud\n"
            + "tu49A/0KZu4PBjrFMYTSEWGNJez3Fb2VsJwylVl6HivwbP61FhlYfyksCzQQFU71\n"
            + "+x7Nmybp7PmpEBECr3deoZKQ/acNHn0iwb0It+YqV5+TquQebqgwK6WCLsMuiYKT\n"
            + "bg/ch9Rhxbq22yrVgWHh6epp\n"
            + "-----END PRIVATE KEY-----"
    ),
    ROOT_CA(
        "root-ca.pem",
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIExjCCA66gAwIBAgIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcNAQEL\n"
            + "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt\n"
            + "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl\n"
            + "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v\n"
            + "dCBDQTAeFw0yMzA4MjkwNDIwMDNaFw0yMzA5MjgwNDIwMDNaMIGPMRMwEQYKCZIm\n"
            + "iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQ\n"
            + "RXhhbXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290\n"
            + "IENBMSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0EwggEiMA0GCSqG\n"
            + "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEPyN7J9VGPyJcQmCBl5TGwfSzvVdWwoQU\n"
            + "j9aEsdfFJ6pBCDQSsj8Lv4RqL0dZra7h7SpZLLX/YZcnjikrYC+rP5OwsI9xEE/4\n"
            + "U98CsTBPhIMgqFK6SzNE5494BsAk4cL72dOOc8tX19oDS/PvBULbNkthQ0aAF1dg\n"
            + "vbrHvu7hq7LisB5ZRGHVE1k/AbCs2PaaKkn2jCw/b+U0Ml9qPuuEgz2mAqJDGYoA\n"
            + "WSR4YXrOcrmPuRqbws464YZbJW898/0Pn/U300ed+4YHiNYLLJp51AMkR4YEw969\n"
            + "VRPbWIvLrd0PQBooC/eLrL6rvud/GpYhdQEUx8qcNCKd4bz3OaQ5AgMBAAGjggEW\n"
            + "MIIBEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU\n"
            + "F4ffoFrrZhKn1dD4uhJFPLcrAJwwgc8GA1UdIwSBxzCBxIAUF4ffoFrrZhKn1dD4\n"
            + "uhJFPLcrAJyhgZWkgZIwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ\n"
            + "k/IsZAEZFgdleGFtcGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYD\n"
            + "VQQLDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUg\n"
            + "Q29tIEluYy4gUm9vdCBDQYIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcN\n"
            + "AQELBQADggEBAIopqco/k9RSjouTeKP4z0EVUxdD4qnNh1GLSRqyAVe0aChyKF5f\n"
            + "qt1Bd1XCY8D16RgekkKGHDpJhGCpel+vtIoXPBxUaGQNYxmJCf5OzLMODlcrZk5i\n"
            + "jHIcv/FMeK02NBcz/WQ3mbWHVwXLhmwqa2zBsF4FmPCJAbFLchLhkAv1HJifHbnD\n"
            + "jQzlKyl5jxam/wtjWxSm0iyso0z2TgyzY+MESqjEqB1hZkCFzD1xtUOCxbXgtKae\n"
            + "dgfHVFuovr3fNLV3GvQk0s9okDwDUcqV7DSH61e5bUMfE84o3of8YA7+HUoPV5Du\n"
            + "8sTOKRf7ncGXdDRA8aofW268pTCuIu3+g/Y=\n"
            + "-----END CERTIFICATE-----"
    );

    private final String fileName;
    private final String content;

    DemoCertificate(String fileName, String content) {
        this.fileName = fileName;
        this.content = content;
    }

    public String getFileName() {
        return fileName;
    }

    public String getContent() {
        return content;
    }
}

/**
 * The environment in which the script is being executed
 */
enum ExecutionEnvironment {
    demo, // default value
    test // to be used only for tests
}
