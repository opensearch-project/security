package org.opensearch.security.tools;

import org.junit.Test;
import org.mockito.Mockito;

public class OpenSearchAdminTests {
    /**
     * Tests all help options
     */
    @Test
    public void testHelpOptions() throws Exception {
        String[] args1 = {"help"};

        OpenSearchAdmin mockOpenSearchAdmin = Mockito.mock(OpenSearchAdmin.class);
        OpenSearchAdmin openSearchAdmin = OpenSearchAdmin.getInstance();
        Mockito.doCallRealMethod().when(mockOpenSearchAdmin).main(Mockito.any());
        mockOpenSearchAdmin.helpOptions = openSearchAdmin.helpOptions;
        mockOpenSearchAdmin.commands = openSearchAdmin.commands;

        mockOpenSearchAdmin.main(args1);
        Mockito.verify(mockOpenSearchAdmin, Mockito.times(1)).printHelp();

        String[] args2 = {"-h"};
        mockOpenSearchAdmin.main(args2);
        Mockito.verify(mockOpenSearchAdmin, Mockito.times(2)).printHelp();

        String[] args3 = {"--help"};
        mockOpenSearchAdmin.main(args3);
        Mockito.verify(mockOpenSearchAdmin, Mockito.times(3)).printHelp();
    }

    /**
     * Tests setup-passwords invokes the right underlying command
     */
    @Test
    public void testValidArguments() throws Exception {
        String[] args1 = {"setup-passwords"};
        PasswordSetup passwordSetup = Mockito.mock(PasswordSetup.class);
        Mockito.when(passwordSetup.execute(args1)).thenReturn(0);
        OpenSearchAdmin openSearchAdmin = OpenSearchAdmin.getInstance();
        openSearchAdmin.main(args1);
        Mockito.verify(passwordSetup, Mockito.times(1)).execute(args1);

        String[] args2 = {"setup-passwords", "help"};
        Mockito.when(passwordSetup.execute(args2)).thenReturn(0);
        openSearchAdmin.main(args2);
        Mockito.verify(passwordSetup, Mockito.times(2)).execute(args2);
    }

    /**
     * Tests undefined action
     */
    @Test
    public void testInvalidArguments() throws Exception {
        String[] args1 = {"undefined-input"};
        OpenSearchAdmin mockOpenSearchAdmin = Mockito.mock(OpenSearchAdmin.class);
        OpenSearchAdmin openSearchAdmin = OpenSearchAdmin.getInstance();
        Mockito.doCallRealMethod().when(mockOpenSearchAdmin).main(args1);
        mockOpenSearchAdmin.helpOptions = openSearchAdmin.helpOptions;
        mockOpenSearchAdmin.commands = openSearchAdmin.commands;

        mockOpenSearchAdmin.main(args1);
        Mockito.verify(mockOpenSearchAdmin, Mockito.times(1)).logInvalidUsage();
    }
}
