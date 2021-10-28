/*
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.auditlog.impl;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.config.AuditConfig;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.SpecialPermission;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Strings;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.env.Environment;
import org.opensearch.index.engine.Engine.Delete;
import org.opensearch.index.engine.Engine.DeleteResult;
import org.opensearch.index.engine.Engine.Index;
import org.opensearch.index.engine.Engine.IndexResult;
import org.opensearch.index.get.GetResult;
import org.opensearch.index.shard.ShardId;
import org.opensearch.rest.RestRequest;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;

import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import com.fasterxml.jackson.databind.JsonNode;
import com.flipkart.zjsonpatch.JsonDiff;
import com.google.common.io.BaseEncoding;

import static org.opensearch.common.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;

public abstract class AbstractAuditLog implements AuditLog {
    protected final Logger log = LogManager.getLogger(this.getClass());

    private final ThreadPool threadPool;
    private final IndexNameExpressionResolver resolver;
    private final ClusterService clusterService;
    private final Settings settings;
    private volatile AuditConfig.Filter auditConfigFilter;
    private final String securityIndex;
    private volatile ComplianceConfig complianceConfig;
    private final Environment environment;
    private AtomicBoolean externalConfigLogged = new AtomicBoolean();

    protected abstract void enableRoutes();

    private static final List<String> writeClasses = new ArrayList<>();
    {
        writeClasses.add(IndexRequest.class.getSimpleName());
        writeClasses.add(UpdateRequest.class.getSimpleName());
        writeClasses.add(BulkRequest.class.getSimpleName());
        writeClasses.add(BulkShardRequest.class.getSimpleName());
        writeClasses.add(DeleteRequest.class.getSimpleName());
    }

    protected AbstractAuditLog(Settings settings, final ThreadPool threadPool, final IndexNameExpressionResolver resolver, final ClusterService clusterService, final Environment environment) {
        super();
        this.threadPool = threadPool;
        this.settings = settings;
        this.resolver = resolver;
        this.clusterService = clusterService;
        this.securityIndex = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.environment = environment;
    }

    protected void onAuditConfigFilterChanged(AuditConfig.Filter auditConfigFilter) {
        this.auditConfigFilter = auditConfigFilter;
        this.auditConfigFilter.log(log);
    }

    protected void onComplianceConfigChanged(ComplianceConfig complianceConfig) {
        this.complianceConfig = complianceConfig;
        enableRoutes();
        this.complianceConfig.log(log);
        // External config is audit logged only once per node start and config from index is not available at that time.
        // The audit event will be created only if enabled and not already logged.
        // external_config parameter in audit config can be hot-reloaded which will impact functionality of this function.
        logExternalConfig();
    }

    @Override
    public ComplianceConfig getComplianceConfig() {
        return this.complianceConfig;
    }

    @Override
    public void logFailedLogin(String effectiveUser, boolean securityadmin, String initiatingUser, TransportRequest request, Task task) {
        final String action = null;

        if(!checkTransportFilter(AuditCategory.FAILED_LOGIN, action, effectiveUser, request)) {
            return;
        }

        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.FAILED_LOGIN, getOrigin(), action, null, effectiveUser, securityadmin, initiatingUser, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), securityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }


    @Override
    public void logFailedLogin(String effectiveUser, boolean securityadmin, String initiatingUser, RestRequest request) {

        if(!checkRestFilter(AuditCategory.FAILED_LOGIN, effectiveUser, request)) {
            return;
        }

        AuditMessage msg = new AuditMessage(AuditCategory.FAILED_LOGIN, clusterService, getOrigin(), Origin.REST);
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        msg.addRestRequestInfo(request, auditConfigFilter);
        msg.addInitiatingUser(initiatingUser);
        msg.addEffectiveUser(effectiveUser);
        msg.addIsAdminDn(securityadmin);

        save(msg);
    }

    @Override
    public void logSucceededLogin(String effectiveUser, boolean securityadmin, String initiatingUser, TransportRequest request, String action, Task task) {

        if(!checkTransportFilter(AuditCategory.AUTHENTICATED, action, effectiveUser, request)) {
            return;
        }

        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.AUTHENTICATED, getOrigin(), action, null, effectiveUser, securityadmin, initiatingUser,remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), securityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logSucceededLogin(String effectiveUser, boolean securityadmin, String initiatingUser, RestRequest request) {

        if(!checkRestFilter(AuditCategory.AUTHENTICATED, effectiveUser, request)) {
            return;
        }

        AuditMessage msg = new AuditMessage(AuditCategory.AUTHENTICATED, clusterService, getOrigin(), Origin.REST);
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        msg.addRestRequestInfo(request, auditConfigFilter);
        msg.addInitiatingUser(initiatingUser);
        msg.addEffectiveUser(effectiveUser);
        msg.addIsAdminDn(securityadmin);
        save(msg);
    }

    @Override
    public void logMissingPrivileges(String privilege, String effectiveUser, RestRequest request) {
        if(!checkRestFilter(AuditCategory.MISSING_PRIVILEGES, effectiveUser, request)) {
            return;
        }

        AuditMessage msg = new AuditMessage(AuditCategory.MISSING_PRIVILEGES, clusterService, getOrigin(), Origin.REST);
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        msg.addRestRequestInfo(request, auditConfigFilter);
        msg.addEffectiveUser(effectiveUser);
        save(msg);
    }

    @Override
    public void logGrantedPrivileges(String effectiveUser, RestRequest request) {
        if(!checkRestFilter(AuditCategory.GRANTED_PRIVILEGES, effectiveUser, request)) {
            return;
        }

        AuditMessage msg = new AuditMessage(AuditCategory.GRANTED_PRIVILEGES, clusterService, getOrigin(), Origin.REST);
        msg.addRemoteAddress(getRemoteAddress());
        msg.addRestRequestInfo(request, auditConfigFilter);
        msg.addEffectiveUser(effectiveUser);
        save(msg);
    }

    @Override
    public void logMissingPrivileges(String privilege, TransportRequest request, Task task) {
        final String action = null;

        if(!checkTransportFilter(AuditCategory.MISSING_PRIVILEGES, privilege, getUser(), request)) {
            return;
        }

        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.MISSING_PRIVILEGES, getOrigin(), action, privilege, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), securityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logGrantedPrivileges(String privilege, TransportRequest request, Task task) {
        final String action = null;

        if(!checkTransportFilter(AuditCategory.GRANTED_PRIVILEGES, privilege, getUser(), request)) {
            return;
        }

        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.GRANTED_PRIVILEGES, getOrigin(), action, privilege, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), securityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logIndexEvent(String privilege, TransportRequest request, Task task) {
        if(!checkTransportFilter(AuditCategory.INDEX_EVENT, privilege, getUser(), request)) {
            return;
        }
        // log only cluster admin action
        if (!privilege.startsWith("indices:admin/")) {
            return;
        }
        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.INDEX_EVENT, getOrigin(), null, privilege, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), securityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

        msgs.forEach(this::save);
    }

    @Override
    public void logBadHeaders(TransportRequest request, String action, Task task) {

        if(!checkTransportFilter(AuditCategory.BAD_HEADERS, action, getUser(), request)) {
            return;
        }

        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.BAD_HEADERS, getOrigin(), action, null, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), securityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logBadHeaders(RestRequest request) {

        if(!checkRestFilter(AuditCategory.BAD_HEADERS, getUser(), request)) {
            return;
        }

        AuditMessage msg = new AuditMessage(AuditCategory.BAD_HEADERS, clusterService, getOrigin(), Origin.REST);
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        msg.addRestRequestInfo(request, auditConfigFilter);
        msg.addEffectiveUser(getUser());

        save(msg);
    }

    @Override
    public void logSecurityIndexAttempt(TransportRequest request, String action, Task task) {

        if(!checkTransportFilter(AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT, action, getUser(), request)) {
            return;
        }

        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT, getOrigin(), action, null, getUser(), false, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), securityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logSSLException(TransportRequest request, Throwable t, String action, Task task) {

        if(!checkTransportFilter(AuditCategory.SSL_EXCEPTION, action, getUser(), request)) {
            return;
        }

        final TransportAddress remoteAddress = getRemoteAddress();

        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.SSL_EXCEPTION, Origin.TRANSPORT, action, null, getUser(), false, null, remoteAddress, request,
                getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), securityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), t);

        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logSSLException(RestRequest request, Throwable t) {

        if(!checkRestFilter(AuditCategory.SSL_EXCEPTION, getUser(), request)) {
            return;
        }

        AuditMessage msg = new AuditMessage(AuditCategory.SSL_EXCEPTION, clusterService, Origin.REST, Origin.REST);

        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        msg.addRestRequestInfo(request, auditConfigFilter);
        msg.addException(t);
        msg.addEffectiveUser(getUser());
        save(msg);
    }

    @Override
    public void logDocumentRead(String index, String id, ShardId shardId, Map<String, String> fieldNameValues) {
        final ComplianceConfig complianceConfig = getComplianceConfig();
        if(complianceConfig == null || !complianceConfig.readHistoryEnabledForIndex(index)) {
            return;
        }

        final String initiatingRequestClass = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER);

        if(initiatingRequestClass != null && writeClasses.contains(initiatingRequestClass)) {
            return;
        }

        AuditCategory category = securityIndex.equals(index)? AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ: AuditCategory.COMPLIANCE_DOC_READ;

        String effectiveUser = getUser();
        if(!checkComplianceFilter(category, effectiveUser, getOrigin(), complianceConfig)) {
            return;
        }

        if(fieldNameValues != null && !fieldNameValues.isEmpty()) {
            AuditMessage msg = new AuditMessage(category, clusterService, getOrigin(), null);
            TransportAddress remoteAddress = getRemoteAddress();
            msg.addRemoteAddress(remoteAddress);
            msg.addEffectiveUser(effectiveUser);
            msg.addIndices(new String[]{index});
            msg.addResolvedIndices(new String[]{index});
            msg.addShardId(shardId);
            //msg.addIsAdminDn(securityadmin);
            msg.addId(id);

            try {
                if(complianceConfig.shouldLogReadMetadataOnly()) {
                    try {
                        XContentBuilder builder = XContentBuilder.builder(JsonXContent.jsonXContent);
                        builder.startObject();
                        builder.field("field_names", fieldNameValues.keySet());
                        builder.endObject();
                        builder.close();
                        msg.addUnescapedJsonToRequestBody(Strings.toString(builder));
                    } catch (IOException e) {
                        log.error(e.toString(), e);
                    }
                } else {
                    if(securityIndex.equals(index) && !"tattr".equals(id)) {
                        try {
                            Map<String, String> map = fieldNameValues.entrySet().stream()
                                    .collect(Collectors.toMap(entry -> "id", entry -> new String(BaseEncoding.base64().decode(((Entry<String, String>) entry).getValue()), StandardCharsets.UTF_8)));
                            msg.addSecurityConfigMapToRequestBody(Utils.convertJsonToxToStructuredMap(map.get("id")), id);
                        } catch (Exception e) {
                            msg.addSecurityConfigMapToRequestBody(fieldNameValues, id);
                        }
                    } else {
                        msg.addMapToRequestBody(fieldNameValues);
                    }
                }
            } catch (Exception e) {
                log.error("Unable to generate request body for {} and {}",msg.toPrettyString(),fieldNameValues, e);
            }

            save(msg);
        }

    }

    @Override
    public void logDocumentWritten(ShardId shardId, GetResult originalResult, Index currentIndex, IndexResult result) {
        final ComplianceConfig complianceConfig = getComplianceConfig();
        if(complianceConfig == null || !complianceConfig.writeHistoryEnabledForIndex(shardId.getIndexName())) {
            return;
        }

        AuditCategory category = securityIndex.equals(shardId.getIndexName())? AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE: AuditCategory.COMPLIANCE_DOC_WRITE;

        String effectiveUser = getUser();

        if(!checkComplianceFilter(category, effectiveUser, getOrigin(), complianceConfig)) {
            return;
        }

        final String id = currentIndex.id();
        AuditMessage msg = new AuditMessage(category, clusterService, getOrigin(), null);
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        msg.addEffectiveUser(effectiveUser);
        msg.addIndices(new String[]{shardId.getIndexName()});
        msg.addResolvedIndices(new String[]{shardId.getIndexName()});
        msg.addId(id);
        msg.addShardId(shardId);
        msg.addComplianceDocVersion(result.getVersion());
        msg.addComplianceOperation(result.isCreated()?Operation.CREATE:Operation.UPDATE);

        if(complianceConfig.shouldLogDiffsForWrite() && originalResult != null && originalResult.isExists() && originalResult.internalSourceRef() != null) {
            try {
                String originalSource = null;
                String currentSource = null;
                if (securityIndex.equals(shardId.getIndexName())) {
                    try (XContentParser parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, originalResult.internalSourceRef(), XContentType.JSON)) {
                        Object base64 = parser.map().values().iterator().next();
                        if(base64 instanceof String) {
                            originalSource = (new String(BaseEncoding.base64().decode((String) base64)));
                        } else {
                            originalSource = XContentHelper.convertToJson(originalResult.internalSourceRef(), false, XContentType.JSON);
                        }
                    } catch (Exception e) {
                        log.error(e);
                    }

                    try (XContentParser parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, currentIndex.source(), XContentType.JSON)) {
                        Object base64 = parser.map().values().iterator().next();
                        if(base64 instanceof String) {
                            currentSource = (new String(BaseEncoding.base64().decode((String) base64)));
                        } else {
                            currentSource = XContentHelper.convertToJson(currentIndex.source(), false, XContentType.JSON);
                        }
                    } catch (Exception e) {
                        log.error(e);
                    }
                    final JsonNode diffnode = JsonDiff.asJson(DefaultObjectMapper.objectMapper.readTree(originalSource), DefaultObjectMapper.objectMapper.readTree(currentSource));
                    msg.addSecurityConfigWriteDiffSource(diffnode.size() == 0 ? "" : diffnode.toString(), id);
                } else {
                    originalSource = XContentHelper.convertToJson(originalResult.internalSourceRef(), false, XContentType.JSON);
                    currentSource = XContentHelper.convertToJson(currentIndex.source(), false, XContentType.JSON);
                    final JsonNode diffnode = JsonDiff.asJson(DefaultObjectMapper.objectMapper.readTree(originalSource), DefaultObjectMapper.objectMapper.readTree(currentSource));
                    msg.addComplianceWriteDiffSource(diffnode.size() == 0 ? "" : diffnode.toString());
                }
            } catch (Exception e) {
                log.error("Unable to generate diff for {}",msg.toPrettyString(),e);
            }
        }


        if (!complianceConfig.shouldLogWriteMetadataOnly()){
            if(securityIndex.equals(shardId.getIndexName())) {
                //current source, normally not null or empty
                try (XContentParser parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, currentIndex.source(), XContentType.JSON)) {
                   Object base64 = parser.map().values().iterator().next();
                   if(base64 instanceof String) {
                       msg.addSecurityConfigContentToRequestBody(new String(BaseEncoding.base64().decode((String) base64)), id);
                   } else {
                       msg.addSecurityConfigTupleToRequestBody(new Tuple<XContentType, BytesReference>(XContentType.JSON, currentIndex.source()), id);
                   }
                } catch (Exception e) {
                    log.error(e);
                }

                //if we want to have msg.ComplianceWritePreviousSource we need to do the same as above

            } else {

                //previous source, can be null if document is a new one
                //msg.ComplianceWritePreviousSource(new Tuple<XContentType, BytesReference>(XContentType.JSON, originalResult.internalSourceRef()));

                //current source, normally not null or empty
                msg.addTupleToRequestBody(new Tuple<XContentType, BytesReference>(XContentType.JSON, currentIndex.source()));
            }

        }


        save(msg);
    }

    @Override
    public void logDocumentDeleted(ShardId shardId, Delete delete, DeleteResult result) {

        String effectiveUser = getUser();

        final ComplianceConfig complianceConfig = getComplianceConfig();
        if (complianceConfig == null || !complianceConfig.isEnabled() || !checkComplianceFilter(AuditCategory.COMPLIANCE_DOC_WRITE, effectiveUser, getOrigin(), complianceConfig)) {
            return;
        }

        AuditMessage msg = new AuditMessage(AuditCategory.COMPLIANCE_DOC_WRITE, clusterService, getOrigin(), null);
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        msg.addEffectiveUser(effectiveUser);
        msg.addIndices(new String[]{shardId.getIndexName()});
        msg.addResolvedIndices(new String[]{shardId.getIndexName()});
        msg.addId(delete.id());
        msg.addShardId(shardId);
        msg.addComplianceDocVersion(result.getVersion());
        msg.addComplianceOperation(Operation.DELETE);
        save(msg);
    }

    protected void logExternalConfig() {

        final ComplianceConfig complianceConfig = getComplianceConfig();
        if (complianceConfig == null || !complianceConfig.isEnabled() || !complianceConfig.shouldLogExternalConfig() || !checkComplianceFilter(AuditCategory.COMPLIANCE_EXTERNAL_CONFIG, null, getOrigin(), complianceConfig) || externalConfigLogged.getAndSet(true)) {
            return;
        }

        log.info("logging external config");
        final Map<String, Object> configAsMap = Utils.convertJsonToxToStructuredMap(settings);

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        final Map<String, String> envAsMap = AccessController.doPrivileged(new PrivilegedAction<Map<String, String>>() {
            @Override
            public Map<String, String> run() {
                return System.getenv();
            }
        });

        final Map propsAsMap = AccessController.doPrivileged(new PrivilegedAction<Map>() {
            @Override
            public Map run() {
                return System.getProperties();
            }
        });

        final String sha256 = DigestUtils.sha256Hex(configAsMap.toString()+envAsMap.toString()+propsAsMap.toString());
        AuditMessage msg = new AuditMessage(AuditCategory.COMPLIANCE_EXTERNAL_CONFIG, clusterService, null, null);

        try (XContentBuilder builder = XContentBuilder.builder(XContentType.JSON.xContent())) {
            builder.startObject();
            builder.startObject("external_configuration");
            builder.field("opensearch_yml", configAsMap);
            builder.field("os_environment", envAsMap);
            builder.field("java_properties", propsAsMap);
            builder.field("sha256_checksum", sha256);
            builder.endObject();
            builder.endObject();
            builder.close();
            msg.addUnescapedJsonToRequestBody(Strings.toString(builder));
        } catch (Exception e) {
            log.error("Unable to build message",e);
        }

        Map<String, Path> paths = new HashMap<String, Path>();
        for(String key: settings.keySet()) {
            if(key.startsWith("opendistro_security") &&
                    (key.contains("filepath") || key.contains("file_path"))) {
                String value = settings.get(key);
                if(value != null && !value.isEmpty()) {
                    Path path = value.startsWith("/")?Paths.get(value):environment.configFile().resolve(value);
                    paths.put(key, path);
                }
            }
        }
        msg.addFileInfos(paths);


        save(msg);
    }

    private Origin getOrigin() {
        String origin = (String) threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);

        if(origin == null && threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER) != null) {
            origin = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER);
        }

        return origin == null?null:Origin.valueOf(origin);
    }

    private TransportAddress getRemoteAddress() {
        TransportAddress address = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        if(address == null && threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER) != null) {
            address = new TransportAddress((InetSocketAddress) Base64Helper.deserializeObject(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER)));
        }
        return address;
    }

    private String getUser() {
        User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if(user == null && threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER) != null) {
            user = (User) Base64Helper.deserializeObject(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER));
        }
        return user==null?null:user.getName();
    }

    private Map<String, String> getThreadContextHeaders() {
        return threadPool.getThreadContext().getHeaders();
    }

    @VisibleForTesting
    boolean checkTransportFilter(final AuditCategory category, final String action, final String effectiveUser, TransportRequest request) {
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("Check category:{}, action:{}, effectiveUser:{}, request:{}", category, action, effectiveUser, request==null?null:request.getClass().getSimpleName());
        }


        if (!auditConfigFilter.isTransportApiAuditEnabled()) {
            return false;
        }

        //skip internals
        if (action != null && action.startsWith("internal:")) {
            return false;
        }

        if (auditConfigFilter.isAuditDisabled(effectiveUser)) {

            if (isTraceEnabled) {
                log.trace("Skipped audit log message because of user {} is ignored", effectiveUser);
            }

            return false;
        }

        if (request != null && (auditConfigFilter.isRequestAuditDisabled(action) || auditConfigFilter.isRequestAuditDisabled(request.getClass().getSimpleName()))) {

            if (isTraceEnabled) {
                log.trace("Skipped audit log message because request {} is ignored", action+"#"+request.getClass().getSimpleName());
            }

            return false;
        }

        if (!auditConfigFilter.getDisabledTransportCategories().contains(category)) {
            return true;
        } else {
            if (isTraceEnabled) {
                log.trace("Skipped audit log message because category {} not enabled", category);
            }
            return false;
        }


        //skip internal:*
        //check transport audit enabled
        //check category enabled
        //check action
        //check ignoreAuditUsers

    }

    private boolean checkComplianceFilter(final AuditCategory category, final String effectiveUser, Origin origin, ComplianceConfig complianceConfig) {
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("Check for COMPLIANCE category:{}, effectiveUser:{}, origin: {}", category, effectiveUser, origin);
        }

        if(origin == Origin.LOCAL && effectiveUser == null && category != AuditCategory.COMPLIANCE_EXTERNAL_CONFIG) {
            if (isTraceEnabled) {
                log.trace("Skipped compliance log message because of null user and local origin");
            }
            return false;
        }

        if(category == AuditCategory.COMPLIANCE_DOC_READ || category == AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ) {

            if (effectiveUser != null && complianceConfig.isComplianceReadAuditDisabled(effectiveUser)) {

                if (isTraceEnabled) {
                    log.trace("Skipped compliance log message because of user {} is ignored", effectiveUser);
                }
                return false;
            }
        }

        if(category == AuditCategory.COMPLIANCE_DOC_WRITE || category == AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE) {
            if (effectiveUser != null && complianceConfig.isComplianceWriteAuditDisabled(effectiveUser)) {

                if (isTraceEnabled) {
                    log.trace("Skipped compliance log message because of user {} is ignored", effectiveUser);
                }
                return false;
            }
        }

        return true;
    }

    @VisibleForTesting
    boolean checkRestFilter(final AuditCategory category, final String effectiveUser, RestRequest request) {
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("Check for REST category:{}, effectiveUser:{}, request:{}", category, effectiveUser, request==null?null:request.path());
        }

        if (!auditConfigFilter.isRestApiAuditEnabled()) {
            return false;
        }

        if (auditConfigFilter.isAuditDisabled(effectiveUser)) {

            if (isTraceEnabled) {
                log.trace("Skipped audit log message because of user {} is ignored", effectiveUser);
            }

            return false;
        }

        if (request != null && auditConfigFilter.isRequestAuditDisabled(request.path())) {

            if (isTraceEnabled) {
                log.trace("Skipped audit log message because request {} is ignored", request.path());
            }

            return false;
        }

        if (!auditConfigFilter.getDisabledRestCategories().contains(category)) {
            return true;
        } else {
            if (isTraceEnabled) {
                log.trace("Skipped audit log message because category {} not enabled", category);
            }
            return false;
        }


        //check rest audit enabled
        //check category enabled
        //check action
        //check ignoreAuditUsers
    }


    protected abstract void save(final AuditMessage msg);
}
