package org.opensearch.security.tools;

import java.util.*;

public class OpenSearchAdmin {
    protected Map<String, Command> commands = new LinkedHashMap<>();
    Set<String> helpOptions = new HashSet<>(Arrays.asList("--help", "-h", "help"));

    protected String REPORT_ISSUE_MESSAGE =
            "If you face any issues, please report at https://github.com/opensearch-project/security/issues/new/choose";
    protected String INVALID_USAGE_MESSAGE = "ERR: Invalid Usage";
    protected String ACTION_USAGE_MESSAGE = "Check usage with:\nopensearch-admin [action] --help";

    private String getSupportedActionsMessage() {
        StringBuilder supportedActionsMessage = new StringBuilder();
        supportedActionsMessage.append("\nList of supported actions:\n");
        for(Map.Entry<String, Command> entry: commands.entrySet()) {
            supportedActionsMessage.append(String.format("%-20s%s", entry.getKey(), entry.getValue().describe()));
            supportedActionsMessage.append("\n");
        }
        return supportedActionsMessage.toString();
    }

//    static {
////        System.out.println("A tool for installing and configuring OpenSearch security");
////        commands.put("setup-passwords", new PasswordSetup());
////        commands.put("setup-certificates", new ToBeImplemented());
////        commands.put("rotate-passwords", new ToBeImplemented());
////        commands.put("hasher", new ToBeImplemented());
////        commands.put("audit-config", new ToBeImplemented());
////        commands.put("dynamic-config", new ToBeImplemented());
//    }

    void initialize() {
        commands.put("setup-passwords", new PasswordSetup());
    }

    private static OpenSearchAdmin opensearchAdminInstance = null;

    private OpenSearchAdmin() {
        System.out.println("A tool for installing and configuring OpenSearch security");
        initialize();
    }

    public static OpenSearchAdmin getInstance() {
        if(null == opensearchAdminInstance)
            opensearchAdminInstance = new OpenSearchAdmin();

        return opensearchAdminInstance;
    }

    protected void logInvalidUsage() {
        System.out.println(INVALID_USAGE_MESSAGE);
        printHelp();
    }

    protected void printHelp() {
        System.out.println(getSupportedActionsMessage());
        System.out.println(ACTION_USAGE_MESSAGE);
        System.out.println(REPORT_ISSUE_MESSAGE);
    }

    public static void main(String[] args) throws Exception {
        OpenSearchAdmin openSearchAdmin = getInstance();
        if(args.length == 0 || (args.length == 1 && openSearchAdmin.helpOptions.contains(args[0]))) {
            openSearchAdmin.printHelp();
            return;
        }
        else if(!openSearchAdmin.commands.containsKey(args[0])) {
            openSearchAdmin.logInvalidUsage();
            return;
        }
        else if(args.length > 1 && openSearchAdmin.helpOptions.contains(args[1])) {
            openSearchAdmin.commands.get(args[0]).usage();
            return;
        }

        try {
            openSearchAdmin.commands.get(args[0]).main(Arrays.copyOfRange(args, 0, args.length));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
