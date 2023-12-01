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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.tools.democonfig.util.NoExitSecurityManager;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.opensearch.security.tools.democonfig.Installer.BASE_DIR;
import static org.opensearch.security.tools.democonfig.Installer.FILE_EXTENSION;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_BIN_DIR;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_CONF_DIR;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_CONF_FILE;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_INSTALL_TYPE;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_LIB_PATH;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_PLUGINS_DIR;
import static org.opensearch.security.tools.democonfig.Installer.OPENSEARCH_VERSION;
import static org.opensearch.security.tools.democonfig.Installer.OS;
import static org.opensearch.security.tools.democonfig.Installer.RPM_DEB_OPENSEARCH_FILE;
import static org.opensearch.security.tools.democonfig.Installer.SCRIPT_DIR;
import static org.opensearch.security.tools.democonfig.Installer.SECURITY_VERSION;
import static org.opensearch.security.tools.democonfig.Installer.assumeyes;
import static org.opensearch.security.tools.democonfig.Installer.cluster_mode;
import static org.opensearch.security.tools.democonfig.Installer.determineInstallType;
import static org.opensearch.security.tools.democonfig.Installer.environment;
import static org.opensearch.security.tools.democonfig.Installer.finishScriptExecution;
import static org.opensearch.security.tools.democonfig.Installer.gatherUserInputs;
import static org.opensearch.security.tools.democonfig.Installer.initializeVariables;
import static org.opensearch.security.tools.democonfig.Installer.initsecurity;
import static org.opensearch.security.tools.democonfig.Installer.printScriptHeaders;
import static org.opensearch.security.tools.democonfig.Installer.printVariables;
import static org.opensearch.security.tools.democonfig.Installer.readOptions;
import static org.opensearch.security.tools.democonfig.Installer.resetState;
import static org.opensearch.security.tools.democonfig.Installer.setBaseDir;
import static org.opensearch.security.tools.democonfig.Installer.setOpenSearchVariables;
import static org.opensearch.security.tools.democonfig.Installer.setSecurityVariables;
import static org.opensearch.security.tools.democonfig.Installer.skip_updates;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createDirectory;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createFile;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.deleteDirectoryRecursive;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

public class InstallerTests {
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final InputStream originalIn = System.in;

    @Before
    public void setUpStreams() {
        System.setOut(new PrintStream(outContent));
        resetState();
    }

    @After
    public void restoreStreams() {
        System.setOut(originalOut);
        System.setIn(originalIn);
    }

    @Test
    public void testPrintScriptHeaders() {
        printScriptHeaders();

        String expectedOutput = "### OpenSearch Security Demo Installer"
            + System.lineSeparator()
            + "### ** Warning: Do not use on production or public reachable systems **"
            + System.lineSeparator();
        assertThat(expectedOutput, equalTo(outContent.toString()));
    }

    @Test
    public void testReadOptions_withoutHelpOption() {
        // All options except Help `-h`
        String[] validOptions = { "/scriptDir", "-y", "-i", "-c", "-s", "-t" };
        readOptions(validOptions);

        assertEquals("/scriptDir", SCRIPT_DIR);
        assertThat(assumeyes, is(true));
        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));
        assertEquals(0, skip_updates);
        assertEquals(ExecutionEnvironment.TEST, environment);
    }

    @Test
    public void testReadOptions_help() {
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            String[] helpOption = { "/scriptDir", "-h" };
            readOptions(helpOption);

            assertThat(outContent.toString(), containsString("install_demo_configuration.sh [-y] [-i] [-c]"));
            assertThat(outContent.toString(), containsString("-h show help"));
            assertThat(outContent.toString(), containsString("-y confirm all installation dialogues automatically"));
            assertThat(outContent.toString(), containsString("-i initialize Security plugin with default configuration"));
            assertThat(outContent.toString(), containsString("-c enable cluster mode by binding to all network interfaces"));
            assertThat(outContent.toString(), containsString("-s skip updates if config is already applied to opensearch.yml"));
            assertThat(outContent.toString(), containsString("-t set the execution environment to `test` to skip password validation"));
            assertThat(outContent.toString(), containsString("Should be used only for testing. (default is set to `demo`)"));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(0) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testGatherUserInputs_withoutAssumeYes() {
        // -i & -c option is not passed
        String[] validOptions = { "/scriptDir" };
        readOptions(validOptions);
        assertThat(assumeyes, is(false));
        assertThat(initsecurity, is(false));
        assertThat(cluster_mode, is(false));

        // set initsecurity and cluster_mode to no
        readInputStream("y" + System.lineSeparator() + "n" + System.lineSeparator() + "n" + System.lineSeparator()); // pass all 3 inputs as
                                                                                                                     // y
        gatherUserInputs();

        assertThat(outContent.toString(), containsString("Install demo certificates?"));
        assertThat(outContent.toString(), containsString("Initialize Security Modules?"));
        assertThat(outContent.toString(), containsString("Cluster mode requires additional setup of:"));
        assertThat(outContent.toString(), containsString("  - Virtual memory (vm.max_map_count)" + System.lineSeparator()));
        assertThat(outContent.toString(), containsString("Enable cluster mode?"));

        assertThat(initsecurity, is(false));
        assertThat(cluster_mode, is(false));

        outContent.reset();

        // set initsecurity and cluster_mode to no
        readInputStream("y" + System.lineSeparator() + "y" + System.lineSeparator() + "y" + System.lineSeparator()); // pass all 3 inputs as
                                                                                                                     // y
        gatherUserInputs();

        assertThat(outContent.toString(), containsString("Install demo certificates?"));
        assertThat(outContent.toString(), containsString("Initialize Security Modules?"));
        assertThat(outContent.toString(), containsString("Cluster mode requires additional setup of:"));
        assertThat(outContent.toString(), containsString("  - Virtual memory (vm.max_map_count)" + System.lineSeparator()));
        assertThat(outContent.toString(), containsString("Enable cluster mode?"));

        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));

        outContent.reset();

        // no to demo certificates
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            readInputStream("n" + System.lineSeparator() + "n" + System.lineSeparator() + "n" + System.lineSeparator());
            gatherUserInputs();

            assertThat(outContent.toString(), containsString("Install demo certificates?"));
            assertThat(outContent.toString(), not(containsString("Initialize Security Modules?")));
            assertThat(outContent.toString(), not(containsString("Cluster mode requires additional setup of:")));
            assertThat(outContent.toString(), not(containsString("  - Virtual memory (vm.max_map_count)" + System.lineSeparator())));
            assertThat(outContent.toString(), not(containsString("Enable cluster mode?")));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(0) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }

        outContent.reset();

        // pass initsecurity and cluster_mode options
        String[] validOptionsIC = { "/scriptDir", "-i", "-c" };
        readOptions(validOptionsIC);
        assertThat(assumeyes, is(false));
        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));

        readInputStream("y" + System.lineSeparator() + "y" + System.lineSeparator() + "y" + System.lineSeparator()); // pass all 3 inputs as
                                                                                                                     // y
        gatherUserInputs();

        assertThat(outContent.toString(), containsString("Install demo certificates?"));
        assertThat(outContent.toString(), not(containsString("Initialize Security Modules?")));
        assertThat(outContent.toString(), not(containsString("Enable cluster mode?")));

        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));
    }

    @Test
    public void testGatherInputs_withAssumeYes() {
        String[] validOptionsYes = { "/scriptDir", "-y" };
        readOptions(validOptionsYes);
        assertThat(assumeyes, is(true));

        gatherUserInputs();

        assertThat(initsecurity, is(true));
        assertThat(cluster_mode, is(true));
    }

    @Test
    public void testInitializeVariables_setBaseDir_invalidPath() {
        String[] invalidScriptDirPath = { "/scriptDir", "-y" };
        readOptions(invalidScriptDirPath);

        assertThrows("Expected NullPointerException to be thrown", NullPointerException.class, Installer::initializeVariables);

        resetState();

        String[] invalidScriptDirPath2 = { "/opensearch/plugins/opensearch-security/tools", "-y" };
        readOptions(invalidScriptDirPath2);

        try {
            System.setSecurityManager(new NoExitSecurityManager());

            initializeVariables();
            assertThat(outContent.toString(), containsString("DEBUG: basedir does not exist"));
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testSetBaseDir_valid() {
        String currentDir = System.getProperty("user.dir");

        String[] validBaseDir = { currentDir, "-y" };
        readOptions(validBaseDir);

        setBaseDir();

        String expectedBaseDirValue = new File(currentDir).getParentFile().getParentFile().getParentFile().getAbsolutePath()
            + File.separator;
        assertThat(BASE_DIR, equalTo(expectedBaseDirValue));
    }

    @Test
    public void testSetOpenSearchVariables_invalidPath() {
        String currentDir = System.getProperty("user.dir");

        String[] validBaseDir = { currentDir, "-y" };
        readOptions(validBaseDir);

        try {
            System.setSecurityManager(new NoExitSecurityManager());

            setBaseDir();
            setOpenSearchVariables();

            assertThat(outContent.toString(), containsString("Unable to determine OpenSearch config file. Quit."));
            assertThat(outContent.toString(), containsString("Unable to determine OpenSearch bin directory. Quit."));
            assertThat(outContent.toString(), containsString("Unable to determine OpenSearch plugins directory. Quit."));
            assertThat(outContent.toString(), containsString("Unable to determine OpenSearch lib directory. Quit."));

        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }

        String expectedBaseDirValue = new File(currentDir).getParentFile().getParentFile().getParentFile().getAbsolutePath()
            + File.separator;
        String expectedOpensearchConfFilePath = expectedBaseDirValue + "config" + File.separator + "opensearch.yml";
        String expectedOpensearchBinDirPath = expectedBaseDirValue + "bin" + File.separator;
        String expectedOpensearchPluginDirPath = expectedBaseDirValue + "plugins" + File.separator;
        String expectedOpensearchLibDirPath = expectedBaseDirValue + "lib" + File.separator;
        String expectedOpensearchInstallType = determineInstallType();

        assertThat(OPENSEARCH_CONF_FILE, equalTo(expectedOpensearchConfFilePath));
        assertThat(OPENSEARCH_BIN_DIR, equalTo(expectedOpensearchBinDirPath));
        assertThat(OPENSEARCH_PLUGINS_DIR, equalTo(expectedOpensearchPluginDirPath));
        assertThat(OPENSEARCH_LIB_PATH, equalTo(expectedOpensearchLibDirPath));
        assertThat(OPENSEARCH_INSTALL_TYPE, equalTo(expectedOpensearchInstallType));

    }

    @Test
    public void testDetermineInstallType_windows() {
        OS = "Windows";

        String installType = determineInstallType();

        assertEquals(".zip", installType);
    }

    @Test
    public void testDetermineInstallType_rpm_deb() {
        OS = "Linux";
        String dir = System.getProperty("user.dir");
        BASE_DIR = dir;
        RPM_DEB_OPENSEARCH_FILE = new File(dir);

        String installType = determineInstallType();

        assertEquals("rpm/deb", installType);
    }

    @Test
    public void testDetermineInstallType_default() {
        OS = "Anything else";
        BASE_DIR = "/random-dir";
        String installType = determineInstallType();

        assertEquals(".tar.gz", installType);
    }

    @Test
    public void testSetSecurityVariables() {
        setUpSecurityDirectories();
        setSecurityVariables();

        assertThat(OPENSEARCH_VERSION, is(equalTo("osVersion")));
        assertThat(SECURITY_VERSION, is(equalTo("version")));
        tearDownSecurityDirectories();
    }

    @Test
    public void testSetSecurityVariables_noSecurityPlugin() {
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            setSecurityVariables();
            fail("Expected System.exit(-1) to be called");
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testPrintVariables() {
        OPENSEARCH_INSTALL_TYPE = "installType";
        OS = "OS";
        OPENSEARCH_CONF_DIR = "confDir";
        OPENSEARCH_CONF_FILE = "confFile";
        OPENSEARCH_BIN_DIR = "/bin";
        OPENSEARCH_PLUGINS_DIR = "/plugins";
        OPENSEARCH_LIB_PATH = "/lib";
        OPENSEARCH_VERSION = "osVersion";
        SECURITY_VERSION = "version";

        printVariables();

        String expectedOutput = "OpenSearch install type: installType on OS"
            + System.lineSeparator()
            + "OpenSearch config dir: confDir"
            + System.lineSeparator()
            + "OpenSearch config file: confFile"
            + System.lineSeparator()
            + "OpenSearch bin dir: /bin"
            + System.lineSeparator()
            + "OpenSearch plugins dir: /plugins"
            + System.lineSeparator()
            + "OpenSearch lib dir: /lib"
            + System.lineSeparator()
            + "Detected OpenSearch Version: osVersion"
            + System.lineSeparator()
            + "Detected OpenSearch Security Version: version"
            + System.lineSeparator();

        assertEquals(expectedOutput, outContent.toString());
    }

    @Test
    public void testFinishScriptExecution() {
        setUpSecurityDirectories();
        SecuritySettingsConfigurer.ADMIN_PASSWORD = "ble";

        finishScriptExecution();

        String securityAdminScriptPath = OPENSEARCH_PLUGINS_DIR
            + "opensearch-security"
            + File.separator
            + "tools"
            + File.separator
            + "securityadmin"
            + FILE_EXTENSION;
        String securityAdminDemoScriptPath = OPENSEARCH_CONF_DIR + "securityadmin_demo" + FILE_EXTENSION;
        setWritePermissions(securityAdminDemoScriptPath);

        String lastLine = SecuritySettingsConfigurer.getSecurityAdminCommands(securityAdminScriptPath)[1];
        // Verify the expected output
        String expectedOutput = "### Success"
            + System.lineSeparator()
            + "### Execute this script now on all your nodes and then start all nodes"
            + System.lineSeparator()
            + "### After the whole cluster is up execute: "
            + System.lineSeparator()
            + lastLine
            + ""
            + System.lineSeparator()
            + "### or run ."
            + File.separator
            + "securityadmin_demo"
            + FILE_EXTENSION
            + System.lineSeparator()
            + "### After that you can also use the Security Plugin ConfigurationGUI"
            + System.lineSeparator()
            + "### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/"
            + SecuritySettingsConfigurer.ADMIN_PASSWORD
            + "."
            + System.lineSeparator()
            + "### (Ignore the SSL certificate warning because we installed self-signed demo certificates)"
            + System.lineSeparator();

        assertEquals(expectedOutput, outContent.toString());

        tearDownSecurityDirectories();
    }

    @Test
    public void testFinishScriptExecution_withInitSecurityEnabled() {
        setUpSecurityDirectories();
        initsecurity = true;
        SecuritySettingsConfigurer.ADMIN_PASSWORD = "ble";

        finishScriptExecution();

        String securityAdminScriptPath = OPENSEARCH_PLUGINS_DIR
            + "opensearch-security"
            + File.separator
            + "tools"
            + File.separator
            + "securityadmin"
            + FILE_EXTENSION;
        String securityAdminDemoScriptPath = OPENSEARCH_CONF_DIR + "securityadmin_demo" + FILE_EXTENSION;
        setWritePermissions(securityAdminDemoScriptPath);

        String lastLine = SecuritySettingsConfigurer.getSecurityAdminCommands(securityAdminScriptPath)[1];
        String expectedOutput = "### Success"
            + System.lineSeparator()
            + "### Execute this script now on all your nodes and then start all nodes"
            + System.lineSeparator()
            + "### OpenSearch Security will be automatically initialized."
            + System.lineSeparator()
            + "### If you like to change the runtime configuration "
            + System.lineSeparator()
            + "### change the files in .."
            + File.separator
            + ".."
            + File.separator
            + ".."
            + File.separator
            + "config"
            + File.separator
            + "opensearch-security and execute: "
            + System.lineSeparator()
            + lastLine
            + System.lineSeparator()
            + "### or run ."
            + File.separator
            + "securityadmin_demo"
            + FILE_EXTENSION
            + System.lineSeparator()
            + "### To use the Security Plugin ConfigurationGUI"
            + System.lineSeparator()
            + "### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/"
            + SecuritySettingsConfigurer.ADMIN_PASSWORD
            + "."
            + System.lineSeparator()
            + "### (Ignore the SSL certificate warning because we installed self-signed demo certificates)"
            + System.lineSeparator();

        assertEquals(expectedOutput, outContent.toString());

        tearDownSecurityDirectories();
    }

    private void readInputStream(String input) {
        System.setIn(new ByteArrayInputStream(input.getBytes()));
    }

    public void setUpSecurityDirectories() {
        String currentDir = System.getProperty("user.dir");

        String[] validBaseDir = { currentDir, "-y" };
        readOptions(validBaseDir);
        setBaseDir();
        OPENSEARCH_PLUGINS_DIR = BASE_DIR + "plugins" + File.separator;
        OPENSEARCH_LIB_PATH = BASE_DIR + "lib" + File.separator;
        OPENSEARCH_CONF_DIR = BASE_DIR + "test-conf" + File.separator;

        createDirectory(OPENSEARCH_PLUGINS_DIR);
        createDirectory(OPENSEARCH_LIB_PATH);
        createDirectory(OPENSEARCH_CONF_DIR);
        createDirectory(OPENSEARCH_PLUGINS_DIR + "opensearch-security");
        createFile(OPENSEARCH_LIB_PATH + "opensearch-osVersion.jar");
        createFile(OPENSEARCH_PLUGINS_DIR + "opensearch-security" + File.separator + "opensearch-security-version.jar");
        createFile(OPENSEARCH_CONF_DIR + File.separator + "securityadmin_demo.sh");
    }

    public void tearDownSecurityDirectories() {
        // Clean up testing directories or files
        deleteDirectoryRecursive(OPENSEARCH_PLUGINS_DIR);
        deleteDirectoryRecursive(OPENSEARCH_LIB_PATH);
        deleteDirectoryRecursive(OPENSEARCH_CONF_DIR);
    }

    static void setWritePermissions(String filePath) {
        if (!OS.toLowerCase().contains("win")) {
            Path file = Paths.get(filePath);
            Set<PosixFilePermission> perms = new HashSet<>();
            perms.add(PosixFilePermission.OWNER_WRITE);
            try {
                Files.setPosixFilePermissions(file, perms);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
