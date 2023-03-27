package org.opensearch.security.extensions;

import static org.opensearch.security.extensions.ExtensionHelper.extensionServiceAccountExists;

public class ExtensionRegistrationResponse {

    //TODO: May not need this class; could move into ExtensionHelper
    private final String extensionUniqueId;

    private boolean registrationComplete;

    public ExtensionRegistrationResponse(String extensionUniqueId) {
        this.extensionUniqueId = extensionUniqueId;
        this.registrationComplete = extensionIsRegistered();
    }

    public boolean extensionIsRegistered(){ // Todo: This should make sure that the registration is propagated to all nodes, not sure how to do that

        if (registrationComplete) {
            return true;
        }
        if (extensionServiceAccountExists(this.extensionUniqueId)) {
            this.registrationComplete = true;
            return true;
        }
        return false;
    }

    public String getExtensionUniqueId() { return extensionUniqueId; }

    public boolean getRegistrationComplete() { return registrationComplete; }


}
