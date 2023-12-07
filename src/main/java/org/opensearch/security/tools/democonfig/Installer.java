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
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

/**
 * This class installs demo configuration for security plugin
 */
public class Installer {

    private static Installer instance;

    private static SecuritySettingsConfigurer securitySettingsConfigurer;

    private static CertificateGenerator certificateGenerator;

    boolean assumeyes = false;
    boolean initsecurity = false;
    boolean cluster_mode = false;
    int skip_updates = -1;
    String SCRIPT_DIR;
    String BASE_DIR;
    String OPENSEARCH_CONF_FILE;
    String OPENSEARCH_BIN_DIR;
    String OPENSEARCH_PLUGINS_DIR;
    String OPENSEARCH_LIB_PATH;
    String OPENSEARCH_INSTALL_TYPE;
    String OPENSEARCH_CONF_DIR;
    String OPENSEARCH_VERSION;
    String SECURITY_VERSION;

    ExecutionEnvironment environment = ExecutionEnvironment.DEMO;

    String OS;

    final String FILE_EXTENSION;

    static File RPM_DEB_OPENSEARCH_HOME = new File("/usr/share/opensearch");

    private Installer() {
        this.OS = System.getProperty("os.name") + " " + System.getProperty("os.version") + " " + System.getProperty("os.arch");
        FILE_EXTENSION = OS.toLowerCase().contains("win") ? ".bat" : ".sh";
    }

    public static Installer getInstance() {
        if (instance == null) {
            instance = new Installer();
            securitySettingsConfigurer = new SecuritySettingsConfigurer(instance);
            certificateGenerator = new CertificateGenerator(instance);
        }
        return instance;
    }

    public void installDemoConfiguration(String[] options) {
        readOptions(options);
        printScriptHeaders();
        gatherUserInputs();
        initializeVariables();
        printVariables();
        securitySettingsConfigurer.configureSecuritySettings();
        certificateGenerator.createDemoCertificates();
        finishScriptExecution();
    }

    public static void main(String[] options) {
        Installer installer = Installer.getInstance();
        installer.installDemoConfiguration(options);
    }

    /**
     * Prints headers that indicate the start of script execution
     */
    static void printScriptHeaders() {
        System.out.println("### OpenSearch Security Demo Installer");
        System.out.println("### ** Warning: Do not use on production or public reachable systems **");
    }

    /**
     * Reads the options passed to the script
     * @param options an array of strings containing options passed to the script
     */
    void readOptions(String[] options) {
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
                    skip_updates = 0;
                    break;
                case "-t":
                    environment = ExecutionEnvironment.TEST;
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
    void showHelp() {
        System.out.println("install_demo_configuration.sh [-y] [-i] [-c]");
        System.out.println("  -h show help");
        System.out.println("  -y confirm all installation dialogues automatically");
        System.out.println("  -i initialize Security plugin with default configuration (default is to ask if -y is not given)");
        System.out.println("  -c enable cluster mode by binding to all network interfaces (default is to ask if -y is not given)");
        System.out.println("  -s skip updates if config is already applied to opensearch.yml");
        System.out.println(
            "  -t set the execution environment to `test` to skip password validation. Should be used only for testing. (default is set to `demo`)"
        );
        System.exit(0);
    }

    /**
     * Prompt the user and collect user inputs
     * Input collection will be skipped if -y option was passed
     */
    void gatherUserInputs() {
        if (!assumeyes) {
            try (Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8)) {

                if (!confirmAction(scanner, "Install demo certificates?")) {
                    System.exit(0);
                }

                if (!initsecurity) {
                    initsecurity = confirmAction(scanner, "Initialize Security Modules?");
                }

                if (!cluster_mode) {
                    System.out.println("Cluster mode requires additional setup of:");
                    System.out.println("  - Virtual memory (vm.max_map_count)" + System.lineSeparator());
                    cluster_mode = confirmAction(scanner, "Enable cluster mode?");
                }
            }
        } else {
            initsecurity = true;
            cluster_mode = true;
        }
    }

    /**
     * Helper method to scan user inputs.
     * @param scanner object to be used for scanning user input
     * @param message prompt question
     * @return true or false based on user input
     */
    boolean confirmAction(Scanner scanner, String message) {
        System.out.print(message + " [y/N] ");
        String response = scanner.nextLine();
        return response.equalsIgnoreCase("yes") || response.equalsIgnoreCase("y");
    }

    /**
     * Initialize all class level variables required
     */
    void initializeVariables() {
        setBaseDir();
        setOpenSearchVariables();
        setSecurityVariables();
    }

    /**
     * Sets the base directory to be used by the script
     */
    void setBaseDir() {
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
    void setOpenSearchVariables() {
        OPENSEARCH_CONF_FILE = BASE_DIR + "config" + File.separator + "opensearch.yml";
        OPENSEARCH_BIN_DIR = BASE_DIR + "bin" + File.separator;
        OPENSEARCH_PLUGINS_DIR = BASE_DIR + "plugins" + File.separator;
        OPENSEARCH_LIB_PATH = BASE_DIR + "lib" + File.separator;
        OPENSEARCH_INSTALL_TYPE = determineInstallType();

        Set<String> errorMessages = validatePaths();

        if (!errorMessages.isEmpty()) {
            errorMessages.forEach(System.out::println);
            System.exit(-1);
        }

        OPENSEARCH_CONF_DIR = new File(OPENSEARCH_CONF_FILE).getParent();
        OPENSEARCH_CONF_DIR = new File(OPENSEARCH_CONF_DIR).getAbsolutePath() + File.separator;
    }

    /**
     * Helper method
     * Returns a set of error messages for the paths that didn't contain files/directories
     * @return a set containing error messages if any, empty otherwise
     */
    private Set<String> validatePaths() {
        Set<String> errorMessages = new HashSet<>();
        if (!(new File(OPENSEARCH_CONF_FILE).exists())) {
            errorMessages.add("Unable to determine OpenSearch config file. Quit.");
        }

        if (!(new File(OPENSEARCH_BIN_DIR).exists())) {
            errorMessages.add("Unable to determine OpenSearch bin directory. Quit.");
        }

        if (!(new File(OPENSEARCH_PLUGINS_DIR).exists())) {
            errorMessages.add("Unable to determine OpenSearch plugins directory. Quit.");
        }

        if (!(new File(OPENSEARCH_LIB_PATH).exists())) {
            errorMessages.add("Unable to determine OpenSearch lib directory. Quit.");
        }
        return errorMessages;
    }

    /**
     * Returns the installation type based on the underlying operating system
     * @return will be one of `.zip`, `.tar.gz` or `rpm/deb`
     */
    String determineInstallType() {
        // windows (.bat execution)
        if (OS.toLowerCase().contains("win")) {
            return ".zip";
        }

        // other OS (.sh execution)
        if (RPM_DEB_OPENSEARCH_HOME.exists() && RPM_DEB_OPENSEARCH_HOME.equals(new File(BASE_DIR))) {
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
    void setSecurityVariables() {
        if (!(new File(OPENSEARCH_PLUGINS_DIR + "opensearch-security").exists())) {
            System.out.println("OpenSearch Security plugin not installed. Quit.");
            System.exit(-1);
        }

        // Extract OpenSearch version and Security version
        File[] opensearchLibFiles = new File(OPENSEARCH_LIB_PATH).listFiles(
            pathname -> pathname.getName().matches("opensearch-core-(.*).jar")
        );

        if (opensearchLibFiles != null && opensearchLibFiles.length > 0) {
            OPENSEARCH_VERSION = opensearchLibFiles[0].getName().replaceAll("opensearch-core-(.*).jar", "$1");
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
    void printVariables() {
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
     * Prints end of script execution message and creates security admin demo file.
     */
    void finishScriptExecution() {
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

            securitySettingsConfigurer.createSecurityAdminDemoScript(securityAdminScriptPath, securityAdminDemoScriptPath);

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
            try (BufferedReader reader = new BufferedReader(new FileReader(securityAdminDemoScriptPath, StandardCharsets.UTF_8))) {
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

            System.out.println(
                "### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/"
                    + SecuritySettingsConfigurer.ADMIN_PASSWORD
                    + "."
            );
            System.out.println("### (Ignore the SSL certificate warning because we installed self-signed demo certificates)");

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public static void resetInstance() {
        instance = null;
    }
}
