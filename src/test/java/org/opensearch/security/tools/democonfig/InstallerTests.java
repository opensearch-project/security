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

// CS-SUPPRESS-SINGLE: RegexpSingleline extension key-word is used in file ext variable
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
import static org.opensearch.security.tools.democonfig.Installer.RPM_DEB_OPENSEARCH_HOME;
import static org.opensearch.security.tools.democonfig.Installer.printScriptHeaders;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createDirectory;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.createFile;
import static org.opensearch.security.tools.democonfig.util.DemoConfigHelperUtil.deleteDirectoryRecursive;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

public class InstallerTests {
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final InputStream originalIn = System.in;

    private static Installer installer;

    @Before
    public void setUpStreams() {
        System.setOut(new PrintStream(outContent));
        installer = Installer.getInstance();
        installer.buildOptions();
    }

    @After
    public void restoreStreams() {
        System.setOut(originalOut);
        System.setIn(originalIn);
        Installer.resetInstance();
    }

    @Test
    public void testPrintScriptHeaders() {
        printScriptHeaders();

        String expectedOutput = "### OpenSearch Security Demo Installer"
            + System.lineSeparator()
            + "### ** Warning: Do not use on production or public reachable systems **"
            + System.lineSeparator();
        assertThat(outContent.toString(), equalTo(expectedOutput));
    }

    @Test
    public void testReadOptions_withoutHelpOption() {
        // All options except Help `-h`
        String[] validOptions = { "/scriptDir", "-y", "-i", "-c", "-s", "-t" };
        installer.readOptions(validOptions);

        assertThat(installer.SCRIPT_DIR, equalTo("/scriptDir"));
        assertThat(installer.assumeyes, is(true));
        assertThat(installer.initsecurity, is(true));
        assertThat(installer.cluster_mode, is(true));
        assertThat(installer.skip_updates, equalTo(0));
        assertThat(installer.environment, equalTo(ExecutionEnvironment.TEST));
    }

    @Test
    public void testReadOptions_help() {
        try {
            System.setSecurityManager(new NoExitSecurityManager());
            String[] helpOption = { "/scriptDir", "-h" };
            installer.readOptions(helpOption);
        } catch (SecurityException e) {
            // if help text printed correctly then exit code 0 is expected
            assertThat(e.getMessage(), equalTo("System.exit(0) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }

        verifyStdOutContainsString("usage: install_demo_configuration" + installer.FILE_EXTENSION + " [-c] [-h] [-i] [-s] [-t] [-y]");
    }

    @Test
    public void testGatherUserInputs_withoutAssumeYes() {
        // -i & -c option is not passed
        String[] validOptions = { "/scriptDir" };
        installer.readOptions(validOptions);
        assertThat(installer.assumeyes, is(false));
        assertThat(installer.initsecurity, is(false));
        assertThat(installer.cluster_mode, is(false));

        // set initsecurity and cluster_mode to no
        readInputStream("y" + System.lineSeparator() + "n" + System.lineSeparator() + "n" + System.lineSeparator()); // pass all 3 inputs as
                                                                                                                     // y
        installer.gatherUserInputs();

        verifyStdOutContainsString("Install demo certificates?");
        verifyStdOutContainsString("Initialize Security Modules?");
        verifyStdOutContainsString("Cluster mode requires additional setup of:");
        verifyStdOutContainsString("  - Virtual memory (vm.max_map_count)" + System.lineSeparator());
        verifyStdOutContainsString("Enable cluster mode?");

        assertThat(installer.initsecurity, is(false));
        assertThat(installer.cluster_mode, is(false));

        outContent.reset();

        // set initsecurity and cluster_mode to no
        readInputStream("y" + System.lineSeparator() + "y" + System.lineSeparator() + "y" + System.lineSeparator()); // pass all 3 inputs as
                                                                                                                     // y
        installer.gatherUserInputs();

        verifyStdOutContainsString("Install demo certificates?");
        verifyStdOutContainsString("Initialize Security Modules?");
        verifyStdOutContainsString("Cluster mode requires additional setup of:");
        verifyStdOutContainsString("  - Virtual memory (vm.max_map_count)" + System.lineSeparator());
        verifyStdOutContainsString("Enable cluster mode?");

        assertThat(installer.initsecurity, is(true));
        assertThat(installer.cluster_mode, is(true));

        outContent.reset();

        // no to demo certificates
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            readInputStream("n" + System.lineSeparator() + "n" + System.lineSeparator() + "n" + System.lineSeparator());
            installer.gatherUserInputs();
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(0) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
        verifyStdOutContainsString("Install demo certificates?");
        verifyStdOutDoesNotContainString("Initialize Security Modules?");
        verifyStdOutDoesNotContainString("Cluster mode requires additional setup of:");
        verifyStdOutDoesNotContainString("  - Virtual memory (vm.max_map_count)" + System.lineSeparator());
        verifyStdOutDoesNotContainString("Enable cluster mode?");

        outContent.reset();

        // pass initsecurity and cluster_mode options
        String[] validOptionsIC = { "/scriptDir", "-i", "-c" };
        installer.readOptions(validOptionsIC);
        assertThat(installer.assumeyes, is(false));
        assertThat(installer.initsecurity, is(true));
        assertThat(installer.cluster_mode, is(true));

        readInputStream("y" + System.lineSeparator() + "y" + System.lineSeparator() + "y" + System.lineSeparator()); // pass all 3 inputs as
                                                                                                                     // y
        installer.gatherUserInputs();

        verifyStdOutContainsString("Install demo certificates?");
        verifyStdOutDoesNotContainString("Initialize Security Modules?");
        verifyStdOutDoesNotContainString("Enable cluster mode?");

        assertThat(installer.initsecurity, is(true));
        assertThat(installer.cluster_mode, is(true));
    }

    @Test
    public void testGatherInputs_withAssumeYes() {
        String[] validOptionsYes = { "/scriptDir", "-y" };
        installer.readOptions(validOptionsYes);
        assertThat(installer.assumeyes, is(true));

        installer.gatherUserInputs();

        assertThat(installer.initsecurity, is(false));
        assertThat(installer.cluster_mode, is(false));
    }

    @Test
    public void testInitializeVariables_setBaseDir_invalidPath() {
        String[] invalidScriptDirPath = { "/scriptDir", "-y" };
        installer.readOptions(invalidScriptDirPath);

        assertThrows("Expected NullPointerException to be thrown", NullPointerException.class, installer::initializeVariables);

        String[] invalidScriptDirPath2 = { "/opensearch/plugins/opensearch-security/tools", "-y" };
        installer.readOptions(invalidScriptDirPath2);

        try {
            System.setSecurityManager(new NoExitSecurityManager());
            installer.initializeVariables();
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }

        verifyStdOutContainsString("DEBUG: basedir does not exist");
    }

    @Test
    public void testSetBaseDir_valid() {
        String currentDir = System.getProperty("user.dir");

        String[] validBaseDir = { currentDir, "-y" };
        installer.readOptions(validBaseDir);

        installer.setBaseDir();

        String expectedBaseDirValue = new File(currentDir).getParentFile().getParentFile().getParentFile().getAbsolutePath()
            + File.separator;
        assertThat(installer.BASE_DIR, equalTo(expectedBaseDirValue));
    }

    @Test
    public void testSetOpenSearchVariables_invalidPath() {
        String currentDir = System.getProperty("user.dir");

        String[] validBaseDir = { currentDir, "-y" };
        installer.readOptions(validBaseDir);

        try {
            System.setSecurityManager(new NoExitSecurityManager());
            installer.setBaseDir();
            installer.setOpenSearchVariables();
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);

        }
        verifyStdOutContainsString("Unable to determine OpenSearch config file. Quit.");
        verifyStdOutContainsString("Unable to determine OpenSearch bin directory. Quit.");
        verifyStdOutContainsString("Unable to determine OpenSearch plugins directory. Quit.");
        verifyStdOutContainsString("Unable to determine OpenSearch lib directory. Quit.");

        String expectedBaseDirValue = new File(currentDir).getParentFile().getParentFile().getParentFile().getAbsolutePath()
            + File.separator;
        String expectedOpensearchConfFilePath = expectedBaseDirValue + "config" + File.separator + "opensearch.yml";
        String expectedOpensearchBinDirPath = expectedBaseDirValue + "bin" + File.separator;
        String expectedOpensearchPluginDirPath = expectedBaseDirValue + "plugins" + File.separator;
        String expectedOpensearchLibDirPath = expectedBaseDirValue + "lib" + File.separator;
        String expectedOpensearchInstallType = installer.determineInstallType();

        assertThat(installer.OPENSEARCH_CONF_FILE, equalTo(expectedOpensearchConfFilePath));
        assertThat(installer.OPENSEARCH_BIN_DIR, equalTo(expectedOpensearchBinDirPath));
        assertThat(installer.OPENSEARCH_PLUGINS_DIR, equalTo(expectedOpensearchPluginDirPath));
        assertThat(installer.OPENSEARCH_LIB_PATH, equalTo(expectedOpensearchLibDirPath));
        assertThat(installer.OPENSEARCH_INSTALL_TYPE, equalTo(expectedOpensearchInstallType));

    }

    @Test
    public void testDetermineInstallType_windows() {
        installer.OS = "Windows";

        String installType = installer.determineInstallType();

        assertThat(installType, equalTo(".zip"));
    }

    @Test
    public void testDetermineInstallType_rpm_deb() {
        installer.OS = "Linux";
        String dir = System.getProperty("user.dir");
        installer.BASE_DIR = dir;
        RPM_DEB_OPENSEARCH_HOME = new File(dir);

        String installType = installer.determineInstallType();

        assertThat(installType, equalTo("rpm/deb"));
    }

    @Test
    public void testDetermineInstallType_default() {
        installer.OS = "Anything else";
        installer.BASE_DIR = "/random-dir";
        String installType = installer.determineInstallType();

        assertThat(installType, equalTo(".tar.gz"));
    }

    @Test
    public void testSetSecurityVariables() {
        setUpSecurityDirectories();
        installer.setSecurityVariables();

        assertThat(installer.OPENSEARCH_VERSION, is(equalTo("osVersion")));
        assertThat(installer.SECURITY_VERSION, is(equalTo("version")));
        tearDownSecurityDirectories();
    }

    @Test
    public void testSetSecurityVariables_noSecurityPlugin() {
        try {
            System.setSecurityManager(new NoExitSecurityManager());

            installer.setSecurityVariables();
            fail("Expected System.exit(-1) to be called");
        } catch (SecurityException e) {
            assertThat(e.getMessage(), equalTo("System.exit(-1) blocked to allow print statement testing."));
        } finally {
            System.setSecurityManager(null);
        }
    }

    @Test
    public void testPrintVariables() {
        installer.OPENSEARCH_INSTALL_TYPE = "installType";
        installer.OS = "OS";
        installer.OPENSEARCH_CONF_DIR = "confDir";
        installer.OPENSEARCH_CONF_FILE = "confFile";
        installer.OPENSEARCH_BIN_DIR = "/bin";
        installer.OPENSEARCH_PLUGINS_DIR = "/plugins";
        installer.OPENSEARCH_LIB_PATH = "/lib";
        installer.OPENSEARCH_VERSION = "osVersion";
        installer.SECURITY_VERSION = "version";

        installer.printVariables();

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

        assertThat(outContent.toString(), equalTo(expectedOutput));
    }

    @Test
    public void testFinishScriptExecution() {
        setUpSecurityDirectories();
        SecuritySettingsConfigurer.ADMIN_PASSWORD = "ble";

        installer.finishScriptExecution();

        String securityAdminScriptPath = installer.OPENSEARCH_PLUGINS_DIR
            + "opensearch-security"
            + File.separator
            + "tools"
            + File.separator
            + "securityadmin"
            + installer.FILE_EXTENSION;
        String securityAdminDemoScriptPath = installer.OPENSEARCH_CONF_DIR + "securityadmin_demo" + installer.FILE_EXTENSION;
        setWritePermissions(securityAdminDemoScriptPath);

        SecuritySettingsConfigurer securitySettingsConfigurer = new SecuritySettingsConfigurer(installer);
        String lastLine = securitySettingsConfigurer.getSecurityAdminCommands(securityAdminScriptPath)[1];

        String expectedOutput = "### Success"
            + System.lineSeparator()
            + "### Execute this script now on all your nodes and then start all nodes"
            + System.lineSeparator()
            + "### After the whole cluster is up execute: "
            + System.lineSeparator()
            + lastLine
            + System.lineSeparator()
            + "### or run ."
            + File.separator
            + "securityadmin_demo"
            + installer.FILE_EXTENSION
            + System.lineSeparator()
            + "### After that you can also use the Security Plugin ConfigurationGUI"
            + System.lineSeparator()
            + "### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/<your-custom-admin-password>."
            + System.lineSeparator()
            + "### (Ignore the SSL certificate warning because we installed self-signed demo certificates)"
            + System.lineSeparator();

        assertThat(outContent.toString(), equalTo(expectedOutput));

        tearDownSecurityDirectories();
    }

    @Test
    public void testFinishScriptExecution_withInitSecurityEnabled() {
        setUpSecurityDirectories();
        installer.initsecurity = true;
        SecuritySettingsConfigurer.ADMIN_PASSWORD = "ble";

        installer.finishScriptExecution();

        String securityAdminScriptPath = installer.OPENSEARCH_PLUGINS_DIR
            + "opensearch-security"
            + File.separator
            + "tools"
            + File.separator
            + "securityadmin"
            + installer.FILE_EXTENSION;
        String securityAdminDemoScriptPath = installer.OPENSEARCH_CONF_DIR + "securityadmin_demo" + installer.FILE_EXTENSION;
        setWritePermissions(securityAdminDemoScriptPath);

        SecuritySettingsConfigurer securitySettingsConfigurer = new SecuritySettingsConfigurer(installer);
        String lastLine = securitySettingsConfigurer.getSecurityAdminCommands(securityAdminScriptPath)[1];

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
            + installer.FILE_EXTENSION
            + System.lineSeparator()
            + "### To use the Security Plugin ConfigurationGUI"
            + System.lineSeparator()
            + "### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/<your-custom-admin-password>."
            + System.lineSeparator()
            + "### (Ignore the SSL certificate warning because we installed self-signed demo certificates)"
            + System.lineSeparator();

        assertThat(outContent.toString(), equalTo(expectedOutput));

        tearDownSecurityDirectories();
    }

    private void readInputStream(String input) {
        System.setIn(new ByteArrayInputStream(input.getBytes()));
    }

    public void setUpSecurityDirectories() {
        String currentDir = System.getProperty("user.dir");

        String[] validBaseDir = { currentDir, "-y" };
        installer.readOptions(validBaseDir);
        installer.setBaseDir();
        installer.OPENSEARCH_PLUGINS_DIR = installer.BASE_DIR + "plugins" + File.separator;
        installer.OPENSEARCH_LIB_PATH = installer.BASE_DIR + "lib" + File.separator;
        installer.OPENSEARCH_CONF_DIR = installer.BASE_DIR + "test-conf" + File.separator;

        createDirectory(installer.OPENSEARCH_PLUGINS_DIR);
        createDirectory(installer.OPENSEARCH_LIB_PATH);
        createDirectory(installer.OPENSEARCH_CONF_DIR);
        createDirectory(installer.OPENSEARCH_PLUGINS_DIR + "opensearch-security");
        createFile(installer.OPENSEARCH_LIB_PATH + "opensearch-core-osVersion.jar");
        createFile(installer.OPENSEARCH_PLUGINS_DIR + "opensearch-security" + File.separator + "opensearch-security-version.jar");
        createFile(installer.OPENSEARCH_CONF_DIR + File.separator + "securityadmin_demo.sh");
    }

    public void tearDownSecurityDirectories() {
        // Clean up testing directories or files
        deleteDirectoryRecursive(installer.OPENSEARCH_PLUGINS_DIR);
        deleteDirectoryRecursive(installer.OPENSEARCH_LIB_PATH);
        deleteDirectoryRecursive(installer.OPENSEARCH_CONF_DIR);
    }

    static void setWritePermissions(String filePath) {
        if (!installer.OS.toLowerCase().contains("win")) {
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

    private void verifyStdOutContainsString(String s) {
        assertThat(outContent.toString(), containsString(s));
    }

    private void verifyStdOutDoesNotContainString(String s) {
        assertThat(outContent.toString(), not(containsString(s)));
    }
}
