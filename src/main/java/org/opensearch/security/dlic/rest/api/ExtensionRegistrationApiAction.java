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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableList;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.dlic.rest.validation.InternalUsersValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ExtensionRegistrationApiAction extends AbstractApiAction {
    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
            new Route(Method.GET, "/extensions/register"),
            new Route(Method.DELETE, "/extensions/register"),
            new Route(Method.PUT, "/extensions/register"),
            new Route(Method.PATCH, "/extension/register")
    ));

    //Sample Request
    // {
    //  "unique_id": "hello_world",
    //  "indices": "messages",
    //  "protected_indices": {},
    //  "endpoints": "/hello, /goodbye",
    //  "protected_endpoints": "/update/{name}"
    //}

    @Inject
    public ExtensionRegistrationApiAction(final Settings settings, final Path configPath, final RestController controller,
                                  final Client client, final AdminDNs adminDNs, final ConfigurationRepository cl,
                                  final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
                                  ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
                auditLog);
    }

    @Override
    protected boolean hasPermissionsToCreate(final SecurityDynamicConfiguration<?> dynamicConfigFactory,
                                             final Object content,
                                             final String resourceName) {
        return true;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.EXTENSIONREGISTRATION;
    }

    @Override
    protected void handleGet(final RestChannel channel, RestRequest request, Client client, final JsonNode content)
            throws IOException{

        createdResponse(channel, " updated");

        ;
    }

    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        createdResponse(channel, " updated");

        final String uniqueId = request.param("unique_id");
        final List<String> indices = Arrays.asList(request.param("indices"));
        final List<String> protected_indices = Arrays.asList(request.param("protected_indices"));
        final List<String> endpoints = Arrays.asList(request.param("endpoints"));
        final List<String> protected_endpoints = Arrays.asList(request.param("protected_endpoints"));

        final String username = request.param("name");


        if(!validateRequest(request)){
            badRequestResponse(channel, "No Extension Unique ID specified.");
            return;
        }

        if(save(request)){
            generateAuthToken();
            createdResponse(channel, "'" + uniqueId + "' updated");
        }

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName(), false);

        final ObjectNode contentAsNode = (ObjectNode) content;
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);

        // if password is set, it takes precedence over hash
        final String plainTextPassword = securityJsonNode.get("password").asString();
        final String origHash = securityJsonNode.get("hash").asString();
//        if (plainTextPassword != null && plainTextPassword.length() > 0) {
//            contentAsNode.remove("password");
//            contentAsNode.put("hash", hash(plainTextPassword.toCharArray()));
//        } else if (origHash != null && origHash.length() > 0) {
//            contentAsNode.remove("password");
//        } else if (plainTextPassword != null && plainTextPassword.isEmpty() && origHash == null) {
//            contentAsNode.remove("password");
//        }

        final boolean userExisted = internalUsersConfiguration.exists(username);

        // checks complete, create or update the user
        internalUsersConfiguration.putCObject(username, DefaultObjectMapper.readTree(contentAsNode,  internalUsersConfiguration.getImplementingClass()));

    }

    private boolean save(RestRequest request) {
        return  true;
    }

    private boolean validateRequest(RestRequest request) {
        return true;
    }

    @Override
    protected void filter(SecurityDynamicConfiguration<?> builder) {
        super.filter(builder);
        // replace password hashes in addition. We must not remove them from the
        // Builder since this would remove users completely if they
        // do not have any addition properties like roles or attributes
        builder.clearHashes();
    }

    private String generateAuthToken(){
        return "bearer: 9999999999999999";
    }

    @Override
    protected String getResourceName() {
        return "extensionsregistry";
    }

    @Override
    protected CType getConfigName() {
        return CType.CONFIG;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new InternalUsersValidator(request, isSuperAdmin(), ref, this.settings, params);
    }
}
