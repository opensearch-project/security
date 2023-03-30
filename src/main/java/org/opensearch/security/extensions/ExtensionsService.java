/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.extensions;

import java.io.IOException;
import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.ExceptionsHelper;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchTransportService;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.extensions.DiscoveryExtensionNode;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.transport.TransportService;

/**
 * This class handles extension registration and operations on behalf of the Security Plugin.
 */
public class ExtensionsService {

    ClusterService clusterService;
    TransportService transportService;
    NodeClient nodeClient;
    static ConfigurationRepository configurationRepository;
    String securityIndex;
    Client client;

    protected String getResourceName() {
        return "serviceAccount";
    }
    protected static CType getConfigName() {
        return CType.INTERNALUSERS;
    }

    @Inject
    public ExtensionsService(
            ClusterService clusterService,
            TransportService transportService,
            NodeClient nodeClient,
            ConfigurationRepository configurationRepository,
            Settings settings,
            Client client
    ) {
        this.clusterService = clusterService;
        this.transportService = transportService;
        this.nodeClient = nodeClient;
        this.configurationRepository = configurationRepository;
        this.securityIndex = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME,
                ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.client = client;
    }

    protected void saveAndUpdateConfiguration(final Client client, final CType cType,
                                              final SecurityDynamicConfiguration<?> configuration) {
        final IndexRequest ir = new IndexRequest(this.securityIndex);

        // final String type = "_doc";
        final String id = cType.toLCString();

        configuration.removeStatic();

        try {
            client.index(ir.id(id)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                            .setIfSeqNo(configuration.getSeqNo())
                            .setIfPrimaryTerm(configuration.getPrimaryTerm())
                            .source(id, XContentHelper.toXContent(configuration, XContentType.JSON, false)));
        } catch (IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }

    /**
     * Load data for a given CType
     * @param config CType whose data is to be loaded in-memory
     * @return configuration loaded with given CType data
     */
    protected static final SecurityDynamicConfiguration<?> load(final CType config) {
        SecurityDynamicConfiguration<?> loaded = configurationRepository.getConfigurationsFromIndex(Collections.singleton(config))
                .get(config)
                .deepClone();
        return loaded;
    }

    ObjectMapper mapper = new ObjectMapper();

    public ExtensionRegistrationResponse register(String extensionUniqueId) throws ExtensionRegistrationException, IOException {

        ExtensionRegistrationResponse registrationResponse = new ExtensionRegistrationResponse(extensionUniqueId);
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

    private void addServiceAccount(String extensionUniqueId) throws ExtensionRegistrationException, IOException {

        final String serviceAccountName = extensionUniqueId;
        final DiscoveryExtensionNode extensionInformation = OpenSearchSecurityPlugin.GuiceHolder.getExtensionsManager().getExtensionIdMap().get(extensionUniqueId);
        // extensionInformation.getSecurityConfiguration(); TODO: Need to make it so that we can get the extension configuration information
        // extensionInformation.parseToJson();
        // Add default role option for extensions which do not specify their own role
        final String extensionRole = "opendistro_security_all_access"; // TODO: Swap this to be parsed role with name equal to extension name once configuration reading is live
        final Map<String, String> extensionAttributes = new HashMap<>();
        extensionAttributes.put("service", "true"); // This attribute signifies that the account is a service account

        final String createServiceAccountPayload = "{\n" +
                "  \"opendistro_security_roles\": [\"" + extensionRole + "\"],\n" +
                "  \"attributes\": {\n" + extensionAttributes.toString() + "\n" +
                "  }\n" +
                "}";

        JsonNode actualObj;

        try {
             actualObj = mapper.readTree(createServiceAccountPayload);
        } catch (JsonProcessingException ex) {
            throw new ExtensionRegistrationException("Failed to parse the provided configuration settings. Failed to register extension: " + extensionUniqueId);
        }

        ObjectNode content =  (ObjectNode) actualObj;
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(actualObj);

        // A password cannot be provided for a Service account.
        final String plainTextPassword = securityJsonNode.get("password").asString();
        final String origHash = securityJsonNode.get("hash").asString();
        if (plainTextPassword != null && plainTextPassword.length() > 0) {
            throw new ExtensionRegistrationException("A password cannot be provided for extensions. Failed to register extension: " + extensionUniqueId);
        }

        if (origHash != null && origHash.length() > 0) {
            throw new ExtensionRegistrationException("A password hash cannot be provided for extensions. Failed to register extension: " + extensionUniqueId);
        }
        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName());

        internalUsersConfiguration.putCObject(serviceAccountName, DefaultObjectMapper.readTree(content,  internalUsersConfiguration.getImplementingClass()));

        saveAndUpdateConfiguration(client, CType.INTERNALUSERS, internalUsersConfiguration);

    }

    public static boolean extensionServiceAccountExists(String extensionUniqueId) {

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName());
        return internalUsersConfiguration.exists(extensionUniqueId);
    }
}
