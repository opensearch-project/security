/*
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

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

        OpenSearchAdmin openSearchAdmin = new OpenSearchAdmin();
        OpenSearchAdmin mockOpenSearchAdmin = Mockito.spy(openSearchAdmin);
        mockOpenSearchAdmin.execute(args1);
        Mockito.verify(mockOpenSearchAdmin, Mockito.times(1)).printHelp();

        String[] args2 = {"-h"};
        mockOpenSearchAdmin.execute(args2);
        Mockito.verify(mockOpenSearchAdmin, Mockito.times(2)).printHelp();

        String[] args3 = {"--help"};
        mockOpenSearchAdmin.execute(args3);
        Mockito.verify(mockOpenSearchAdmin, Mockito.times(3)).printHelp();
    }

    /**
     * Tests setup-passwords invokes the right underlying command
     */
    @Test
    public void testValidArguments() throws Exception {
        String[] args1 = {"setup-passwords"};
        String[] args2 = {"setup-passwords", "help"};

        OpenSearchAdmin openSearchAdmin = new OpenSearchAdmin();
        OpenSearchAdmin mockOpenSearchAdmin = Mockito.spy(openSearchAdmin);
        PasswordSetup mockPasswordSetup = Mockito.mock(PasswordSetup.class);
        Mockito.doNothing().when(mockPasswordSetup).main(args1);
        Mockito.doNothing().when(mockPasswordSetup).usage();

        mockOpenSearchAdmin.commands.put("setup-passwords", mockPasswordSetup);

        mockOpenSearchAdmin.execute(args1);
        Mockito.verify(mockPasswordSetup, Mockito.times(1)).main(args1);

        mockOpenSearchAdmin.execute(args2);
        Mockito.verify(mockPasswordSetup, Mockito.times(1)).usage();
    }

    /**
     * Tests undefined action
     */
    @Test
    public void testInvalidArguments() throws Exception {
        String[] args1 = {"undefined-input"};
        OpenSearchAdmin openSearchAdmin = new OpenSearchAdmin();
        OpenSearchAdmin mockOpenSearchAdmin = Mockito.spy(openSearchAdmin);
        mockOpenSearchAdmin.helpOptions = openSearchAdmin.helpOptions;
        mockOpenSearchAdmin.commands = openSearchAdmin.commands;

        mockOpenSearchAdmin.execute(args1);
        Mockito.verify(mockOpenSearchAdmin, Mockito.times(1)).logInvalidUsage();
    }
}
