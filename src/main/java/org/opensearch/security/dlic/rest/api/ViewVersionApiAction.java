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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.configuration.SecurityConfigVersionDocument;
import org.opensearch.security.configuration.SecurityConfigVersionsLoader;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.core.rest.RestStatus.NOT_FOUND;
import static org.opensearch.core.rest.RestStatus.OK;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * REST endpoint:
 *   GET /_plugins/_security/api/version
 *   GET /_plugins/_security/api/version/{versionId}
 */
public class ViewVersionApiAction extends AbstractApiAction {

    private static final Logger LOGGER = LogManager.getLogger(ViewVersionApiAction.class);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(Method.GET, "/version"), new Route(Method.GET, "/version/{versionID}"))
    );

    private final SecurityConfigVersionsLoader versionsLoader;

    public ViewVersionApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies,
        final SecurityConfigVersionsLoader versionsLoader
    ) {
        super(Endpoint.VIEW_VERSION, clusterService, threadPool, securityApiDependencies);
        this.versionsLoader = versionsLoader;

        this.requestHandlersBuilder.add(RestRequest.Method.POST, RequestHandler.methodNotImplementedHandler)
            .add(RestRequest.Method.PATCH, RequestHandler.methodNotImplementedHandler)
            .add(RestRequest.Method.PUT, RequestHandler.methodNotImplementedHandler)
            .add(RestRequest.Method.DELETE, RequestHandler.methodNotImplementedHandler)

            .onGetRequest((restRequest) -> {
                String versionParam = restRequest.param("versionID");
                return handleGetRequest(versionParam);
            });
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType<?> getConfigType() {
        return null;
    }

    private ValidationResult<SecurityConfiguration> handleGetRequest(String versionParam) throws IOException {
        try {
            if (versionParam == null) {
                return viewAllVersions();
            } else {
                return viewSpecificVersion(versionParam);
            }
        } catch (Exception e) {
            return ValidationResult.error(RestStatus.INTERNAL_SERVER_ERROR, payload(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
        }
    }

    private ValidationResult<SecurityConfiguration> viewAllVersions() throws IOException {
        SecurityConfigVersionDocument doc = versionsLoader.loadFullDocument();

        return ValidationResult.error(OK, (builder, params) -> {
            XContentBuilder inner = buildVersionsJsonBuilder(doc.getVersions());
            builder.copyCurrentStructure(JsonXContent.jsonXContent.createParser(null, null, BytesReference.bytes(inner).streamInput()));
            return builder;
        });
    }

    private ValidationResult<SecurityConfiguration> viewSpecificVersion(String versionId) throws IOException {
        SecurityConfigVersionDocument doc = versionsLoader.loadFullDocument();

        var maybeVer = doc.getVersions().stream().filter(v -> versionId.equals(v.getVersion_id())).findFirst();

        if (maybeVer.isEmpty()) {
            return ValidationResult.error(NOT_FOUND, payload(NOT_FOUND, "Version " + versionId + " not found"));
        }

        return ValidationResult.error(OK, (builder, params) -> {
            XContentBuilder inner = buildVersionsJsonBuilder(List.of(maybeVer.get()));
            builder.copyCurrentStructure(JsonXContent.jsonXContent.createParser(null, null, BytesReference.bytes(inner).streamInput()));
            return builder;
        });
    }

    /**
     * Build the JSON structure:
     */

    private XContentBuilder buildVersionsJsonBuilder(List<SecurityConfigVersionDocument.Version<?>> versions) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder().prettyPrint();
        builder.startObject();
        builder.startArray("versions");
        for (SecurityConfigVersionDocument.Version<?> ver : versions) {
            builder.startObject();
            builder.field("version_id", ver.getVersion_id());
            builder.field("timestamp", ver.getTimestamp());
            builder.field("modified_by", ver.getModified_by());
            builder.field("security_configs");
            Map<String, Object> plainConfigs = new LinkedHashMap<>();
            for (Map.Entry<String, SecurityConfigVersionDocument.HistoricSecurityConfig<?>> entry : ver.getSecurity_configs().entrySet()) {
                Map<String, Object> scMap = new LinkedHashMap<>();
                scMap.put("lastUpdated", entry.getValue().getLastUpdated());
                scMap.put("configData", entry.getValue().getConfigData());
                plainConfigs.put(entry.getKey(), scMap);
            }
            builder.map(plainConfigs);

            builder.endObject();
        }
        builder.endArray();
        builder.endObject();
        return builder;
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        request.param("versionID");
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {

            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigLoad(SecurityConfiguration securityConfiguration) {
                return ValidationResult.success(securityConfiguration);
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigDelete(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, Responses.forbiddenMessage("Delete not supported for version view"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, Responses.forbiddenMessage("Change not supported for version view"));
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };
    }
}
