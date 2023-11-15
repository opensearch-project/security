package org.opensearch.security.tools.democonfig;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.opensearch.security.test.SingleClusterTest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class InstallerTests extends SingleClusterTest {
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @BeforeEach
    public void setUpStreams() {
        System.setOut(new PrintStream(outContent));
    }

    @AfterEach
    public void restoreStreams() {
        System.setOut(originalOut);
    }

    @Test
    public void testPrintScriptHeaders() {
        Installer.printScriptHeaders();

        // Expected output
        String expectedOutput = "**************************************************************************\n"
            + "** This tool will be deprecated in the next major release of OpenSearch **\n"
            + "** https://github.com/opensearch-project/security/issues/1755           **\n"
            + "**************************************************************************\n"
            + "\n\n"
            + "### OpenSearch Security Demo Installer\n"
            + "### ** Warning: Do not use on production or public reachable systems **\n";

        assertEquals(expectedOutput, outContent.toString());
    }

    @Test
    public void testReadOptions() {
        // Test case 1: Valid options
        String[] validOptions = { "scriptDir", "-y", "-i", "-c", "-s", "-t" };
        Installer.readOptions(validOptions);

        assertEquals("scriptDir", Installer.SCRIPT_DIR);
        assertTrue(Installer.assumeyes);
        assertTrue(Installer.initsecurity);
        assertTrue(Installer.cluster_mode);
        assertEquals(0, Installer.skip_updates);
        assertEquals(ExecutionEnvironment.test, Installer.environment);

        // Test case 2: Help option
        String[] helpOption = { "scriptDir", "-h" };
        Installer.readOptions(helpOption);

        assertTrue(outContent.toString().contains("install_demo_configuration.sh [-y] [-i] [-c]"));
        assertTrue(outContent.toString().contains("-h show help"));
        assertTrue(outContent.toString().contains("-y confirm all installation dialogues automatically"));
        assertTrue(outContent.toString().contains("-i initialize Security plugin with default configuration"));
        assertTrue(outContent.toString().contains("-c enable cluster mode by binding to all network interfaces"));
        assertTrue(outContent.toString().contains("-s skip updates if config is already applied to opensearch.yml"));
        assertTrue(outContent.toString().contains("-t set the execution environment to `test` to skip password validation"));
        assertTrue(outContent.toString().contains("Should be used only for testing. (default is set to `demo`)"));

        // Reset System.out to restore normal behavior
        System.setOut(System.out);
    }
}
