package org.opensearch.security.extensions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.extensions.DiscoveryExtensionNode;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.dlic.rest.api.AbstractApiAction;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.SecurityJsonNode;

import java.util.*;

/**
 * This class handles extension registration and operations on behalf of the Security Plugin.
 */
public class ExtensionHelper {

    protected String getResourceName() {
        return "serviceAccount";
    }
    protected CType getConfigName() {
        return CType.INTERNALUSERS;
    }

    ObjectMapper mapper = new ObjectMapper();

    public ExtensionRegistrationResponse register(String extensionUniqueId) throws ExtensionRegistrationException {

        ExtensionRegistrationResponse registrationResponse = new ExtensionRegistrationResponse(extensionUniqueId);
        addServiceAccount(extensionUniqueId);
        if (registrationResponse.extensionIsRegistered()) { // Check if this is an old extension
            return registrationResponse;
        }
        addServiceAccount(extensionUniqueId);
        if (registrationResponse.extensionIsRegistered()) { // Confirm it was added
            return registrationResponse;
        }
        else { // Throw if failed to add
            throw new ExtensionRegistrationException("An error occurred when registering extension " + extensionUniqueId);
        }
    }

    private void addServiceAccount(String extensionUniqueId) throws JsonProcessingException, ExtensionRegistrationException {

        final String serviceAccountName = extensionUniqueId;
        final DiscoveryExtensionNode extensionInformation = OpenSearchSecurityPlugin.GuiceHolder.getExtensionsManager().getExtensionIdMap().get(extensionUniqueId);
        // extensionInformation.getSecurityConfiguration(); TODO: Need to make it so that we can get the extension configuration information
        final String extensionRole = "opendistro_security_all_access"; // TODO: Swap this to be parsed role with name equal to extension name once configuration reading is live
        final Map<String, String> extensionAttributes = new HashMap<>();
        extensionAttributes.put("service", "true"); // This attribute signifies that the account is a service account

        final String createServiceAccountPayload = "{\n" +
                "  \"opendistro_security_roles\": [\"" + extensionRole + "\"],\n" +
                "  \"attributes\": {\n" + extensionAttributes.toString() + "\n" +
                "  }\n" +
                "}";

        //TODO: Need to add service account to internal authentication backend

        JsonNode actualObj;

        try {
             actualObj = mapper.readTree(createServiceAccountPayload);
        } catch (JsonProcessingException ex) {
            throw new ExtensionRegistrationException("Failed to parse the provided configuration settings. Failed to register extension: " + extensionUniqueId);
        }

        ObjectNode content =  (ObjectNode) actualObj;
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(content);

        // A password cannot be provided for a Service account.
        final String plainTextPassword = securityJsonNode.get("password").asString();
        final String origHash = securityJsonNode.get("hash").asString();
        if (plainTextPassword != null && plainTextPassword.length() > 0) {
            throw new ExtensionRegistrationException("A password cannot be provided for extensions. Failed to register extension: " + extensionUniqueId);
        } else if (origHash != null && origHash.length() > 0) {
            throw new ExtensionRegistrationException("A password hash cannot be provided for extensions. Failed to register extension: " + extensionUniqueId);
        }

        //TODO: This needs to be able to respond back to core once the account is created.
        // This needs to create the user and put in the configuration, then save and update config for all nodes
        internalUsersConfiguration.putCObject(serviceAccountName, DefaultObjectMapper.readTree(content,  internalUsersConfiguration.getImplementingClass()));
        saveAnUpdateConfigs(client, request, CType.INTERNALUSERS, internalUsersConfiguration, new AbstractApiAction.OnSucessActionListener<IndexResponse>(channel) {

            public void onResponse(IndexResponse response) {
                ExtensionRegistrationResponse extensionRegistrationResponse = new ExtensionRegistrationResponse(extensionUniqueId);
            }
        });

        /*
           1. Could try to call InternalUsersApiAction and use handlePut() to add the service account
           2. Could try to use the pieces of handlePut() directly
         */

    }

    public static boolean extensionServiceAccountExists(String extensionUniqueId) {

        return true;
    }
}


