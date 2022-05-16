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

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class OpenSearchAdmin {
    protected Map<String, Command> commands = new LinkedHashMap<>();
    Set<String> helpOptions = new HashSet<>(Arrays.asList("--help", "-h", "help"));

    private String getSupportedActionsMessage() {
        StringBuilder supportedActionsMessage = new StringBuilder();
        supportedActionsMessage.append("\nList of supported actions:\n");
        for(Map.Entry<String, Command> entry: commands.entrySet()) {
            supportedActionsMessage.append(String.format("%-20s%s", entry.getKey(), entry.getValue().describe()));
            supportedActionsMessage.append("\n");
        }
        return supportedActionsMessage.toString();
    }

    void initialize() {
        commands.put("setup-passwords", new PasswordSetup());
    }

    private static OpenSearchAdmin opensearchAdminInstance = null;

    public OpenSearchAdmin() {

        System.out.println("A tool for installing and configuring OpenSearch security");
        initialize();
    }

    protected void logInvalidUsage() {
        System.out.println("ERR: Invalid Usage");
        printHelp();
    }

    protected void printHelp() {
        System.out.println(getSupportedActionsMessage());
        System.out.println("Check usage with:\nopensearch-admin [action] --help");
        System.out.println("If you face any issues, please report at https://github.com/opensearch-project/security/issues/new/choose");
    }

    public void execute(String[] args) {
        if(args.length == 0 || (args.length == 1 && helpOptions.contains(args[0]))) {
            printHelp();
            return;
        }
        else if(!commands.containsKey(args[0])) {
            logInvalidUsage();
            return;
        }
        else if(args.length > 1 && helpOptions.contains(args[1])) {
            commands.get(args[0]).usage();
            return;
        }

        try {
            commands.get(args[0]).main(Arrays.copyOfRange(args, 0, args.length));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        (new OpenSearchAdmin()).execute(args);
    }
}
