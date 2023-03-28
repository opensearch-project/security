package org.opensearch.security.extensions;

import org.opensearch.security.privileges.DocumentAllowList;

import static org.opensearch.security.extensions.ExtensionsService.extensionServiceAccountExists;

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

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (this.getClass() != obj.getClass()) {
            return false;
        }
        ExtensionRegistrationResponse otherExReg = (ExtensionRegistrationResponse) (obj);
        if (!this.extensionUniqueId.equals(otherExReg.extensionUniqueId)) {
            return false;
            }
        return true;
    }
}
