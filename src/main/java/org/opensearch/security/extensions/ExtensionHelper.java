package org.opensearch.security.extensions;

import org.apache.hc.core5.http.HttpStatus;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.indices.segments.PitSegmentsRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.DeletePitRequest;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.extensions.DiscoveryExtensionNode;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.dlic.rest.api.AbstractApiAction;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.user.User;

import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * This class handles extension registration and operations on behalf of the Security Plugin.
 */
public class ExtensionHelper {

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

    private void addServiceAccount(String extensionUniqueId) {

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

        // checks complete, create or update the user
        internalUsersConfiguration.putCObject(serviceAccountName, DefaultObjectMapper.readTree(contentAsNode,  internalUsersConfiguration.getImplementingClass()));

        saveAnUpdateConfigs(client, request, CType.INTERNALUSERS, internalUsersConfiguration, new AbstractApiAction.OnSucessActionListener<IndexResponse>(channel));
    }

    public static boolean extensionServiceAccountExists(String extensionUniqueId) {

        return true;
    }
}


