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
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.configuration.ConfigurationMap;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.SecurityConfigVersionDocument;
import org.opensearch.security.configuration.SecurityConfigVersionHandler;
import org.opensearch.security.configuration.SecurityConfigVersionsLoader;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.DynamicConfigFactory.SecurityConfigChangeEvent;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import com.flipkart.zjsonpatch.JsonDiff;
import org.greenrobot.eventbus.EventBus;

import static org.opensearch.core.rest.RestStatus.INTERNAL_SERVER_ERROR;
import static org.opensearch.core.rest.RestStatus.NOT_FOUND;
import static org.opensearch.core.rest.RestStatus.OK;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * REST endpoint:
 *   POST /_plugins/_security/api/rollback
 *   POST /_plugins/_security/api/rollback/version/{versionID}
 */
public class RollbackVersionApiAction extends AbstractApiAction {

    private static final Logger log = LogManager.getLogger(RollbackVersionApiAction.class);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/rollback"), new Route(POST, "/rollback/version/{versionID}"))
    );

    private final SecurityConfigVersionsLoader versionsLoader;
    private final ConfigurationRepository configRepository;
    private final Client client;

    public RollbackVersionApiAction(
        ClusterService clusterService,
        ThreadPool threadPool,
        SecurityApiDependencies securityApiDependencies,
        SecurityConfigVersionsLoader versionsLoader,
        ConfigurationRepository configRepository,
        Client client
    ) {
        super(Endpoint.ROLLBACK_VERSION, clusterService, threadPool, securityApiDependencies);

        this.versionsLoader = versionsLoader;
        this.configRepository = configRepository;
        this.client = client;

        this.requestHandlersBuilder.add(RestRequest.Method.GET, methodNotImplementedHandler)
            .add(RestRequest.Method.PATCH, methodNotImplementedHandler)
            .add(RestRequest.Method.PUT, methodNotImplementedHandler)
            .add(RestRequest.Method.DELETE, methodNotImplementedHandler)
            .add(POST, (channel, request, unusedclient) -> {
                ValidationResult<SecurityConfiguration> result = handlePostRequest(request);
                result.valid(securityConfiguration -> {
                    try {
                        XContentBuilder builder = XContentFactory.jsonBuilder().prettyPrint();
                        builder.startObject();
                        builder.field("status", "OK");
                        builder.field("message", "config rolled back to version " + request.param("versionID", "previous"));
                        builder.endObject();
                        channel.sendResponse(new BytesRestResponse(OK, builder));
                    } catch (IOException e) {
                        log.error("Failed to send rollback response", e);
                        channel.sendResponse(new BytesRestResponse(INTERNAL_SERVER_ERROR, e.getMessage()));
                    }
                }).error((status, content) -> {
                    try {
                        XContentBuilder builder = XContentFactory.jsonBuilder().prettyPrint();
                        content.toXContent(builder, null);
                        channel.sendResponse(new BytesRestResponse(status, builder));
                    } catch (IOException e) {
                        log.error("Failed to build error response", e);
                        channel.sendResponse(new BytesRestResponse(INTERNAL_SERVER_ERROR, e.getMessage()));
                    }
                });
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

    private ValidationResult<SecurityConfiguration> handlePostRequest(RestRequest request) throws IOException {
        String versionParam = request.param("versionID");
        try {
            if (versionParam == null) {
                return rollbackToPreviousVersion();
            } else {
                return rollbackToSpecificVersion(versionParam);
            }
        } catch (Exception e) {
            log.error("Rollback request failed", e);
            return ValidationResult.error(INTERNAL_SERVER_ERROR, payload(INTERNAL_SERVER_ERROR, e.getMessage()));
        }
    }

    private ValidationResult<SecurityConfiguration> rollbackToPreviousVersion() throws IOException {
        SecurityConfigVersionDocument doc = versionsLoader.loadFullDocument();
        SecurityConfigVersionsLoader.sortVersionsById(doc.getVersions());
        var versions = doc.getVersions();

        if (versions.size() < 2) {
            return ValidationResult.error(NOT_FOUND, payload(NOT_FOUND, "No previous version available to rollback"));
        }

        String previousVersionId = versions.get(versions.size() - 2).getVersion_id();
        return rollbackCommon(previousVersionId, doc);
    }

    private ValidationResult<SecurityConfiguration> rollbackToSpecificVersion(String versionId) throws IOException {
        SecurityConfigVersionDocument doc = versionsLoader.loadFullDocument();
        SecurityConfigVersionsLoader.sortVersionsById(doc.getVersions());

        var maybeVer = doc.getVersions().stream().filter(v -> versionId.equals(v.getVersion_id())).findFirst();

        if (maybeVer.isEmpty()) {
            return ValidationResult.error(NOT_FOUND, payload(NOT_FOUND, "Version " + versionId + " not found"));
        }

        return rollbackCommon(versionId, doc);
    }

    private ValidationResult<SecurityConfiguration> rollbackCommon(String versionId, SecurityConfigVersionDocument doc) throws IOException {
        SecurityConfigVersionsLoader.sortVersionsById(doc.getVersions());
        var maybeVer = doc.getVersions().stream().filter(v -> versionId.equals(v.getVersion_id())).findFirst().orElse(null);

        if (maybeVer == null) {
            return ValidationResult.error(NOT_FOUND, payload(NOT_FOUND, "Version " + versionId + " not found"));
        }

        try {

            rollbackConfigsToSecurityIndex(maybeVer);

            ThreadContext threadContext = threadPool.getThreadContext();

            EventBus.getDefault()
                .register(
                    new SecurityConfigVersionHandler(configRepository, clusterService.getSettings(), threadContext, threadPool, client)
                );

            EventBus.getDefault().post(new SecurityConfigChangeEvent());

            return ValidationResult.error(OK, (builder, params) -> {
                XContentBuilder inner = buildRollbackResponseJson(versionId);
                builder.copyCurrentStructure(JsonXContent.jsonXContent.createParser(null, null, BytesReference.bytes(inner).streamInput()));
                return builder;
            });

        } catch (Exception e) {
            log.error("Rollback to version {} failed", versionId, e);
            return ValidationResult.error(INTERNAL_SERVER_ERROR, payload(INTERNAL_SERVER_ERROR, "Rollback failed: " + e.getMessage()));
        }
    }

    private void rollbackConfigsToSecurityIndex(SecurityConfigVersionDocument.Version<?> versionData) throws IOException {
        Map<String, SecurityConfigVersionDocument.SecurityConfig<?>> securityConfigs = versionData.getSecurity_configs();
        if (securityConfigs == null || securityConfigs.isEmpty()) {
            throw new IOException("No security configs to rollback in version " + versionData.getVersion_id());
        }

        Map<CType<?>, SecurityDynamicConfiguration<?>> configsToApply = new java.util.HashMap<>();
        Map<CType<?>, SecurityDynamicConfiguration<?>> backups = new java.util.HashMap<>();

        try {

            ConfigurationMap currentConfigs = configRepository.getConfigurationsFromIndex(CType.values(), false, true);

            for (Map.Entry<String, SecurityConfigVersionDocument.SecurityConfig<?>> entry : securityConfigs.entrySet()) {
                String cTypeName = entry.getKey();
                SecurityConfigVersionDocument.SecurityConfig<?> sc = entry.getValue();

                if (sc == null || sc.getConfigData() == null) {
                    log.warn("Skipping cType '{}' due to null configData", cTypeName);
                    continue;
                }

                CType<?> cType = CType.fromString(cTypeName);
                if (cType == null) {
                    throw new IOException("Rollback aborted: Unknown config type '" + cTypeName + "' found in version");
                }

                SecurityDynamicConfiguration<?> currentConfig = currentConfigs.get(cType);
                if (currentConfig == null) {
                    throw new IOException("Rollback aborted: Could not fetch current config for cType '" + cTypeName + "'");
                }

                SecurityDynamicConfiguration<?> sdc = SecurityDynamicConfiguration.empty(cType);
                sdc.setSeqNo(currentConfig.getSeqNo());
                sdc.setPrimaryTerm(currentConfig.getPrimaryTerm());

                for (Map.Entry<String, ?> configEntry : sc.getConfigData().entrySet()) {
                    sdc.putCObject(configEntry.getKey(), configEntry.getValue());
                }

                if (isConfigEqual(currentConfig, sdc)) {
                    log.info("Skipping rollback for cType '{}' as there are no changes", cTypeName);
                    continue;
                }

                backups.put(cType, currentConfig);
                configsToApply.put(cType, sdc);
            }

            for (Map.Entry<CType<?>, SecurityDynamicConfiguration<?>> entry : configsToApply.entrySet()) {
                AbstractApiAction.saveAndUpdateConfigs(securityApiDependencies, client, entry.getKey(), entry.getValue()).actionGet();

                log.info("Rollback: wrote config data for cType={}", entry.getKey().toLCString());
            }
        } catch (Exception e) {
            revertRollbackOnFailure(backups, e);
        }
    }

    private void revertRollbackOnFailure(Map<CType<?>, SecurityDynamicConfiguration<?>> backups, Exception originalException)
        throws IOException {
        log.error("Rollback failed mid-way. Reverting previous updates...", originalException);

        for (Map.Entry<CType<?>, SecurityDynamicConfiguration<?>> entry : backups.entrySet()) {
            try {
                AbstractApiAction.saveAndUpdateConfigs(securityApiDependencies, client, entry.getKey(), entry.getValue()).actionGet();
                log.info("Rollback revert: restored previous config for cType={}", entry.getKey().toLCString());
            } catch (Exception re) {
                log.error("Failed to revert config for cType={}", entry.getKey().toLCString(), re);
            }
        }

        throw new IOException(
            "Rollback aborted and reverted due to failure in writing config: " + originalException.getMessage(),
            originalException
        );
    }

    private XContentBuilder buildRollbackResponseJson(String versionId) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder().prettyPrint();
        builder.startObject();
        builder.field("status", "OK");
        builder.field("message", "config rolled back to version " + versionId);
        builder.endObject();
        return builder;
    }

    private boolean isConfigEqual(SecurityDynamicConfiguration<?> currentConfig, SecurityDynamicConfiguration<?> targetConfig) {
        if (currentConfig.getCEntries().equals(targetConfig.getCEntries())) {
            return true;
        }

        try {
            JsonNode currentJson = DefaultObjectMapper.objectMapper.valueToTree(currentConfig.getCEntries());
            JsonNode targetJson = DefaultObjectMapper.objectMapper.valueToTree(targetConfig.getCEntries());

            JsonNode diff = JsonDiff.asJson(currentJson, targetJson);

            if (!diff.isEmpty()) {
                log.debug("Config difference detected: {}", diff.toString());
            }

            return diff.isEmpty();
        } catch (Exception e) {
            log.error("Failed to compare configs for equality using JsonDiff", e);
            return false;
        }
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
                return ValidationResult.error(RestStatus.FORBIDDEN, Responses.forbiddenMessage("Delete not supported for rollback"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) {
                return ValidationResult.success(securityConfiguration);
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };
    }
}
