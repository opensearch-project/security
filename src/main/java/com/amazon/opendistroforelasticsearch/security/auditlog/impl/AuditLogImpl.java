/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.filter.AuditFilter;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.AuditMessageRouter;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.support.Base64Helper;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.env.Environment;
import org.elasticsearch.index.engine.Engine.Delete;
import org.elasticsearch.index.engine.Engine.DeleteResult;
import org.elasticsearch.index.engine.Engine.Index;
import org.elasticsearch.index.engine.Engine.IndexResult;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportRequest;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class AuditLogImpl implements AuditLog {

    private final Logger log = LogManager.getLogger(this.getClass());
    private final ThreadPool threadPool;
    private final ClusterService clusterService;
    private final Settings settings;
    private final AuditConfig auditConfig;
    private final RequestResolver requestResolver;
    private final ComplianceResolver complianceResolver;
    private final AuditMessageRouter messageRouter;
    private final boolean enabled;
    private final String opendistrosecurityIndex;

    private static final List<String> writeClasses = Arrays.asList(
            IndexRequest.class.getSimpleName(),
            UpdateRequest.class.getSimpleName(),
            BulkRequest.class.getSimpleName(),
            BulkShardRequest.class.getSimpleName(),
            DeleteRequest.class.getSimpleName()
    );

    public AuditLogImpl(final Settings settings,
                        final Path configPath,
                        final Client clientProvider,
                        final ThreadPool threadPool,
                        final IndexNameExpressionResolver indexNameExpressionResolver,
                        final ClusterService clusterService) {
        this.threadPool = threadPool;
        this.settings = settings;
        this.clusterService = clusterService;
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.auditConfig = AuditConfig.getConfig(settings);
        this.requestResolver = new RequestResolver(clusterService, indexNameExpressionResolver, opendistrosecurityIndex, threadPool);
        this.complianceResolver = new ComplianceResolver(clusterService, indexNameExpressionResolver, opendistrosecurityIndex);
        this.messageRouter = new AuditMessageRouter(settings, clientProvider, threadPool, configPath);
        this.messageRouter.setComplianceConfig(auditConfig);
        this.enabled = messageRouter.isEnabled();

        log.info("Message routing enabled: {}", this.enabled);

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            log.debug("Security Manager present");
            sm.checkPermission(new SpecialPermission());
        }

        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    close();
                } catch (final IOException e) {
                    log.warn("Exception while shutting down message router", e);
                }
            }));
            log.debug("Shutdown Hook registered");
            return null;
        });
    }

    @Override
    public void close() throws IOException {
        messageRouter.close();
    }

    @Override
    public AuditConfig getConfig() {
        return auditConfig;
    }

    protected void save(final AuditMessage msg) {
        if (enabled) {
            messageRouter.route(msg);
        }
    }

    @Override
    public void logFailedLogin(final String effectiveUser,
                               final boolean securityAdmin,
                               final String initiatingUser,
                               final TransportRequest request,
                               final Task task) {
        if (!enabled) return;
        if (!AuditFilter.checkTransportFilter(AuditCategory.FAILED_LOGIN, null, effectiveUser, request, auditConfig)) {
            return;
        }

        List<AuditMessage> msgs = requestResolver.resolve(AuditCategory.FAILED_LOGIN, getOrigin(), null, null,
                effectiveUser, securityAdmin, initiatingUser, getRemoteAddress(), request, task, auditConfig, null);

        msgs.forEach(this::save);
    }

    @Override
    public void logFailedLogin(final String effectiveUser,
                               final boolean securityAdmin,
                               final String initiatingUser,
                               final RestRequest request) {
        if (!enabled) return;
        if (!AuditFilter.checkRestFilter(AuditCategory.FAILED_LOGIN, effectiveUser, request, auditConfig)) {
            return;
        }

        AuditMessage msg = new AuditMessage.Builder(AuditCategory.FAILED_LOGIN)
                .addClusterServiceInfo(clusterService)
                .addOrigin(getOrigin())
                .addLayer(Origin.REST)
                .addRemoteAddress(getRemoteAddress())
                .addRequestInfo(request, auditConfig.shouldExcludeSensitiveHeaders())
                .addRequestBody(request, auditConfig.shouldLogRequestBody())
                .addInitiatingUser(initiatingUser)
                .addEffectiveUser(effectiveUser)
                .addIsAdminDn(securityAdmin)
                .build();

        save(msg);
    }

    @Override
    public void logSucceededLogin(final String effectiveUser,
                                  final boolean securityAdmin,
                                  final String initiatingUser,
                                  final TransportRequest request,
                                  final String action,
                                  final Task task) {
        if (!enabled) return;
        if (!AuditFilter.checkTransportFilter(AuditCategory.AUTHENTICATED, action, effectiveUser, request, auditConfig)) {
            return;
        }

        List<AuditMessage> msgs = requestResolver.resolve(AuditCategory.AUTHENTICATED, getOrigin(), action, null,
                effectiveUser, securityAdmin, initiatingUser, getRemoteAddress(), request, task, auditConfig, null);

        msgs.forEach(this::save);
    }

    @Override
    public void logSucceededLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, RestRequest request) {
        if (!enabled) return;
        if (!AuditFilter.checkRestFilter(AuditCategory.AUTHENTICATED, effectiveUser, request, auditConfig)) {
            return;
        }

        AuditMessage msg = new AuditMessage.Builder(AuditCategory.AUTHENTICATED)
                .addClusterServiceInfo(clusterService)
                .addOrigin(getOrigin())
                .addLayer(Origin.REST)
                .addRemoteAddress(getRemoteAddress())
                .addRequestInfo(request, auditConfig.shouldExcludeSensitiveHeaders())
                .addRequestBody(request, auditConfig.shouldLogRequestBody())
                .addInitiatingUser(initiatingUser)
                .addEffectiveUser(effectiveUser)
                .addIsAdminDn(securityAdmin)
                .build();

        save(msg);
    }

    @Override
    public void logMissingPrivileges(final String privilege,
                                     final String effectiveUser,
                                     final RestRequest request) {
        if (!enabled) return;
        if (!AuditFilter.checkRestFilter(AuditCategory.MISSING_PRIVILEGES, effectiveUser, request, auditConfig)) {
            return;
        }

        AuditMessage msg = new AuditMessage.Builder(AuditCategory.MISSING_PRIVILEGES)
                .addClusterServiceInfo(clusterService)
                .addOrigin(getOrigin())
                .addLayer(Origin.REST)
                .addRemoteAddress(getRemoteAddress())
                .addRequestInfo(request, auditConfig.shouldExcludeSensitiveHeaders())
                .addRequestBody(request, auditConfig.shouldLogRequestBody())
                .addEffectiveUser(effectiveUser)
                .build();

        save(msg);
    }

    @Override
    public void logMissingPrivileges(final String privilege,
                                     final TransportRequest request,
                                     final Task task) {
        if (!enabled) return;
        if (!AuditFilter.checkTransportFilter(AuditCategory.MISSING_PRIVILEGES, privilege, getUser(), request, auditConfig)) {
            return;
        }

        List<AuditMessage> msgs = requestResolver.resolve(AuditCategory.MISSING_PRIVILEGES, getOrigin(), null, privilege,
                getUser(), null, null, getRemoteAddress(), request, task, auditConfig, null);

        msgs.forEach(this::save);
    }

    @Override
    public void logGrantedPrivileges(final String privilege,
                                     final TransportRequest request,
                                     final Task task) {
        if (!enabled) return;
        if (!AuditFilter.checkTransportFilter(AuditCategory.GRANTED_PRIVILEGES, privilege, getUser(), request, auditConfig)) {
            return;
        }

        List<AuditMessage> msgs = requestResolver.resolve(AuditCategory.GRANTED_PRIVILEGES, getOrigin(), null,
                privilege, getUser(), null, null, getRemoteAddress(), request, task, auditConfig, null);

        msgs.forEach(this::save);
    }

    @Override
    public void logBadHeaders(final TransportRequest request,
                              final String action,
                              final Task task) {
        if (!enabled) return;
        if (!AuditFilter.checkTransportFilter(AuditCategory.BAD_HEADERS, action, getUser(), request, auditConfig)) {
            return;
        }

        List<AuditMessage> msgs = requestResolver.resolve(AuditCategory.BAD_HEADERS, getOrigin(), action, null,
                getUser(), null, null, getRemoteAddress(), request, task, auditConfig, null);

        msgs.forEach(this::save);
    }

    @Override
    public void logBadHeaders(final RestRequest request) {
        if (!enabled) return;
        if (!AuditFilter.checkRestFilter(AuditCategory.BAD_HEADERS, getUser(), request, auditConfig)) {
            return;
        }

        AuditMessage msg = new AuditMessage.Builder(AuditCategory.BAD_HEADERS)
                .addClusterServiceInfo(clusterService)
                .addOrigin(getOrigin())
                .addLayer(Origin.REST)
                .addRemoteAddress(getRemoteAddress())
                .addRequestInfo(request, auditConfig.shouldExcludeSensitiveHeaders())
                .addRequestBody(request, auditConfig.shouldLogRequestBody())
                .addEffectiveUser(getUser())
                .build();
        save(msg);
    }

    @Override
    public void logSecurityIndexAttempt(final TransportRequest request,
                                        final String action,
                                        final Task task) {
        if (!enabled) return;
        if (!AuditFilter.checkTransportFilter(AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT, action, getUser(), request, auditConfig)) {
            return;
        }

        List<AuditMessage> msgs = requestResolver.resolve(AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT, getOrigin(),
                action, null, getUser(), false, null, getRemoteAddress(), request,
                task, auditConfig, null);

        msgs.forEach(this::save);
    }

    @Override
    public void logSSLException(final TransportRequest request,
                                final Throwable t,
                                final String action,
                                final Task task) {
        if (!enabled) return;
        if (!AuditFilter.checkTransportFilter(AuditCategory.SSL_EXCEPTION, action, getUser(), request, auditConfig)) {
            return;
        }

        List<AuditMessage> msgs = requestResolver.resolve(AuditCategory.SSL_EXCEPTION, Origin.TRANSPORT, action,
                null, getUser(), false, null, getRemoteAddress(), request, task, auditConfig, t);

        msgs.forEach(this::save);
    }

    @Override
    public void logSSLException(final RestRequest request,
                                final Throwable t) {
        if (!enabled) return;
        if (!AuditFilter.checkRestFilter(AuditCategory.SSL_EXCEPTION, getUser(), request, auditConfig)) {
            return;
        }

        AuditMessage msg = new AuditMessage.Builder(AuditCategory.SSL_EXCEPTION)
                .addClusterServiceInfo(clusterService)
                .addOrigin(Origin.REST)
                .addLayer(Origin.REST)
                .addRemoteAddress(getRemoteAddress())
                .addRequestInfo(request, auditConfig.shouldExcludeSensitiveHeaders())
                .addRequestBody(request, auditConfig.shouldLogRequestBody())
                .addEffectiveUser(getUser())
                .addException(t)
                .build();
        save(msg);
    }

    @Override
    public void logDocumentRead(final String index,
                                final String id,
                                final ShardId shardId,
                                final Map<String, String> fieldNameValues) {
        if (!enabled) return;

        if (auditConfig == null || !auditConfig.readHistoryEnabledForIndex(index)) {
            return;
        }

        final String initiatingRequestClass = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER);
        if (initiatingRequestClass != null && writeClasses.contains(initiatingRequestClass)) {
            return;
        }

        AuditCategory category = opendistrosecurityIndex.equals(index) ? AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ : AuditCategory.COMPLIANCE_DOC_READ;
        String effectiveUser = getUser();
        if (!AuditFilter.checkComplianceFilter(category, effectiveUser, getOrigin(), auditConfig)) {
            return;
        }

        if (fieldNameValues != null && !fieldNameValues.isEmpty()) {
            AuditMessage msg = complianceResolver.resolve(getOrigin(), getRemoteAddress(), index, id, shardId, fieldNameValues, effectiveUser, auditConfig);
            save(msg);
        }
    }

    @Override
    public void logDocumentWritten(final ShardId shardId,
                                   final GetResult originalResult,
                                   final Index currentIndex,
                                   final IndexResult result) {
        if (!enabled) return;

        String effectiveUser = getUser();
        AuditCategory category = opendistrosecurityIndex.equals(shardId.getIndexName()) ? AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE : AuditCategory.COMPLIANCE_DOC_WRITE;
        if (!AuditFilter.checkComplianceFilter(category, effectiveUser, getOrigin(), auditConfig)) {
            return;
        }

        if (auditConfig == null || !auditConfig.writeHistoryEnabledForIndex(shardId.getIndexName())) {
            return;
        }

        AuditMessage msg = complianceResolver.resolve(getOrigin(), getRemoteAddress(), shardId, originalResult,
                currentIndex, result, effectiveUser, auditConfig);

        save(msg);
    }

    @Override
    public void logDocumentDeleted(final ShardId shardId,
                                   final Delete delete,
                                   final DeleteResult result) {
        if (!enabled) return;

        String effectiveUser = getUser();
        if (!AuditFilter.checkComplianceFilter(AuditCategory.COMPLIANCE_DOC_WRITE, effectiveUser, getOrigin(), auditConfig)) {
            return;
        }

        AuditMessage msg = new AuditMessage.Builder(AuditCategory.COMPLIANCE_DOC_WRITE)
                .addClusterServiceInfo(clusterService)
                .addOrigin(getOrigin())
                .addRemoteAddress(getRemoteAddress())
                .addEffectiveUser(effectiveUser)
                .addIndices(new String[]{shardId.getIndexName()})
                .addResolvedIndices(new String[]{shardId.getIndexName()})
                .addId(delete.id())
                .addShardId(shardId)
                .addComplianceDocVersion(result.getVersion())
                .addComplianceOperation(Operation.DELETE)
                .build();
        save(msg);
    }

    @Override
    public void logExternalConfig(final Settings settings, final Environment environment) {
        if (!enabled) return;
        if (!AuditFilter.checkComplianceFilter(AuditCategory.COMPLIANCE_EXTERNAL_CONFIG, null, getOrigin(), auditConfig)) {
            return;
        }

        final Map<String, Object> configAsMap = Utils.convertJsonToxToStructuredMap(settings);

        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        final Map<String, String> envAsMap = AccessController.doPrivileged((PrivilegedAction<Map<String, String>>) () -> System.getenv());
        final Map propsAsMap = AccessController.doPrivileged((PrivilegedAction<Map>) () -> System.getProperties());

        final String sha256 = DigestUtils.sha256Hex(configAsMap.toString() + envAsMap.toString() + propsAsMap.toString());

        AuditMessage.Builder auditMessageBuilder = new AuditMessage.Builder(AuditCategory.COMPLIANCE_EXTERNAL_CONFIG)
                .addClusterServiceInfo(clusterService);

        try (XContentBuilder builder = XContentBuilder.builder(XContentType.JSON.xContent())) {
            builder.startObject()
                    .startObject("external_configuration")
                    .field("elasticsearch_yml", configAsMap)
                    .field("os_environment", envAsMap)
                    .field("java_properties", propsAsMap)
                    .field("sha256_checksum", sha256)
                    .endObject()
                    .endObject()
                    .close();
            auditMessageBuilder.addUnescapedJsonToRequestBody(Strings.toString(builder));
        } catch (Exception e) {
            log.error("Unable to build message", e);
        }

        Map<String, Path> paths = new HashMap<>();
        for (String key : settings.keySet()) {
            if (key.startsWith("opendistro_security") &&
                    (key.contains("filepath") || key.contains("file_path"))) {
                String value = settings.get(key);
                if (value != null && !value.isEmpty()) {
                    Path path = value.startsWith("/") ? Paths.get(value) : environment.configFile().resolve(value);
                    paths.put(key, path);
                }
            }
        }
        auditMessageBuilder.addFileInfos(paths);

        save(auditMessageBuilder.build());
    }

    private Origin getOrigin() {
        String origin = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);

        if (origin == null && threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER) != null) {
            origin = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER);
        }

        return origin == null ? null : Origin.valueOf(origin);
    }

    private TransportAddress getRemoteAddress() {
        TransportAddress address = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        if (address == null && threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER) != null) {
            address = new TransportAddress((InetSocketAddress) Base64Helper.deserializeObject(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER)));
        }
        return address;
    }

    private String getUser() {
        User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null && threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER) != null) {
            user = (User) Base64Helper.deserializeObject(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER));
        }
        return user == null ? null : user.getName();
    }
}