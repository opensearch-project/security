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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import com.google.common.collect.ImmutableList;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.configuration.ConfigurationMap;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.SecurityConfigVersionDocument;
import org.opensearch.security.configuration.SecurityConfigVersionsLoader;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import com.flipkart.zjsonpatch.JsonDiff;

import static org.opensearch.core.rest.RestStatus.INTERNAL_SERVER_ERROR;
import static org.opensearch.core.rest.RestStatus.NOT_FOUND;
import static org.opensearch.core.rest.RestStatus.OK;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * REST endpoint:
 *   POST /_plugins/_security/api/version/rollback
 *   POST /_plugins/_security/api/version/rollback/{versionID}
 */
public class RollbackVersionApiAction extends AbstractApiAction {

    private static final Logger log = LogManager.getLogger(RollbackVersionApiAction.class);

    private static final long CONFIG_WRITE_TIMEOUT_SECONDS = 20;

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/version/rollback"), new Route(POST, "/version/rollback/{versionID}"))
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

        this.requestHandlersBuilder.allMethodsNotImplemented().override(POST, (channel, request, unusedclient) -> {
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
        var versions = doc.getVersions();

        if (versions.size() < 2) {
            return ValidationResult.error(NOT_FOUND, payload(NOT_FOUND, "No previous version available to rollback"));
        }

        SecurityConfigVersionsLoader.sortVersionsById(doc.getVersions());

        String previousVersionId = versions.get(versions.size() - 2).getVersion_id();
        return rollbackCommon(previousVersionId, doc);
    }

    private ValidationResult<SecurityConfiguration> rollbackToSpecificVersion(String versionId) throws IOException {
        SecurityConfigVersionDocument doc = versionsLoader.loadFullDocument();

        var maybeVer = doc.getVersions().stream().filter(v -> versionId.equals(v.getVersion_id())).findFirst();

        if (maybeVer.isEmpty()) {
            return ValidationResult.error(NOT_FOUND, payload(NOT_FOUND, "Version " + versionId + " not found"));
        }

        return rollbackCommon(versionId, doc);
    }

    private ValidationResult<SecurityConfiguration> rollbackCommon(String versionId, SecurityConfigVersionDocument doc) throws IOException {
        var maybeVer = doc.getVersions().stream().filter(v -> versionId.equals(v.getVersion_id())).findFirst().orElse(null);

        try {

            rollbackConfigsToSecurityIndex(maybeVer);

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
        Map<String, SecurityConfigVersionDocument.HistoricSecurityConfig<?>> securityConfigs = versionData.getSecurity_configs();
        if (securityConfigs == null || securityConfigs.isEmpty()) {
            throw new NullPointerException("No security configs to rollback in version " + versionData.getVersion_id());
        }

        Map<CType<?>, SecurityDynamicConfiguration<?>> configsToApply = new HashMap<>();
        Map<CType<?>, SecurityDynamicConfiguration<?>> backups = new HashMap<>();

        try {

            ConfigurationMap currentConfigs = configRepository.getConfigurationsFromIndex(CType.values(), false, true);

            for (Map.Entry<String, SecurityConfigVersionDocument.HistoricSecurityConfig<?>> entry : securityConfigs.entrySet()) {
                String cTypeName = entry.getKey();
                SecurityConfigVersionDocument.HistoricSecurityConfig<?> sc = entry.getValue();

                CType<?> cType = CType.fromString(cTypeName);
                if (cType == null) {
                    throw new NullPointerException("Rollback aborted: Unknown config type '" + cTypeName + "' found in version");
                }

                if (sc == null || sc.getConfigData() == null) {
                    log.warn("Skipping cType '{}' due to null configData", cTypeName);
                    continue;
                }

                SecurityDynamicConfiguration<?> currentConfig = currentConfigs.get(cType);
                if (currentConfig == null) {
                    throw new IllegalArgumentException("Rollback aborted: Could not fetch current config for cType '" + cTypeName + "'");
                }

                SecurityDynamicConfiguration<?> rollBackConfig = SecurityDynamicConfiguration.empty(cType);
                rollBackConfig.setSeqNo(currentConfig.getSeqNo());
                rollBackConfig.setPrimaryTerm(currentConfig.getPrimaryTerm());

                for (Map.Entry<String, ?> configEntry : sc.getConfigData().entrySet()) {
                    if ("_meta".equals(configEntry.getKey())) {
                        continue; // Avoiding duplicate entry for meta field
                    }
                    rollBackConfig.putCObject(configEntry.getKey(), configEntry.getValue());
                }

                if (isConfigEqual(currentConfig, rollBackConfig)) {
                    log.info("Skipping rollback for cType '{}' as there are no changes", cTypeName);
                    continue;
                }

                backups.put(cType, currentConfig);
                configsToApply.put(cType, rollBackConfig);
            }

            try {
                writeConfigsWithLatch(configsToApply);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IOException("Rollback was interrupted", ie);
            }

        } catch (Exception e) {
            revertRollbackOnFailure(backups, e);
        }
    }

    private void writeConfigsWithLatch(Map<CType<?>, SecurityDynamicConfiguration<?>> configsToApply) throws IOException,
        InterruptedException {
        final var latch = new CountDownLatch(configsToApply.size());

        for (Map.Entry<CType<?>, SecurityDynamicConfiguration<?>> entry : configsToApply.entrySet()) {
            AbstractApiAction.saveAndUpdateConfigsAsync(
                securityApiDependencies,
                client,
                entry.getKey(),
                entry.getValue(),
                new ActionListener<IndexResponse>() {
                    @Override
                    public void onResponse(IndexResponse r) {
                        latch.countDown();
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Rollback: failed to write config for cType={} : {}", entry.getKey().toLCString(), e.getMessage(), e);
                        latch.countDown();
                    }
                }
            );
            log.info("Rollback: wrote config data for cType={}", entry.getKey().toLCString());
        }

        if (!latch.await(CONFIG_WRITE_TIMEOUT_SECONDS, java.util.concurrent.TimeUnit.SECONDS)) {
            throw new IOException("Timeout while writing rolled-back configs");
        }
    }

    private void revertRollbackOnFailure(Map<CType<?>, SecurityDynamicConfiguration<?>> backups, Exception originalException)
        throws IOException {
        log.error("Rollback failed mid-way. Reverting previous updates...", originalException);

        final var latch = new java.util.concurrent.CountDownLatch(backups.size());

        for (Map.Entry<CType<?>, SecurityDynamicConfiguration<?>> entry : backups.entrySet()) {
            AbstractApiAction.saveAndUpdateConfigsAsync(
                securityApiDependencies,
                client,
                entry.getKey(),
                entry.getValue(),
                new ActionListener<IndexResponse>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        log.info("Rollback revert: restored previous config for cType={}", entry.getKey().toLCString());
                        latch.countDown();
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to revert config for cType={}", entry.getKey().toLCString(), e);
                        latch.countDown();
                    }
                }
            );
        }

        try {
            if (!latch.await(CONFIG_WRITE_TIMEOUT_SECONDS, java.util.concurrent.TimeUnit.SECONDS)) {
                throw new IOException("Timeout while reverting rollback configs");
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("Rollback revert was interrupted", ie);
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

    public boolean isConfigEqual(SecurityDynamicConfiguration<?> currentConfig, SecurityDynamicConfiguration<?> targetConfig) {
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
