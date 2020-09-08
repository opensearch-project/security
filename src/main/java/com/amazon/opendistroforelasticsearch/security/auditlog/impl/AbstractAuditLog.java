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
import java.util.stream.Collectors;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;
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

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.support.Base64Helper;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityDeprecationHandler;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.amazon.opendistroforelasticsearch.security.user.User;
import com.fasterxml.jackson.databind.JsonNode;
import com.flipkart.zjsonpatch.JsonDiff;
import com.google.common.io.BaseEncoding;

public abstract class AbstractAuditLog implements AuditLog {
    protected final Logger log = LogManager.getLogger(this.getClass());

    private final ThreadPool threadPool;
    private final IndexNameExpressionResolver resolver;
    private final ClusterService clusterService;
    private final Settings settings;
    private final AuditConfig.Filter auditConfigFilter;
    private final String opendistrosecurityIndex;
    private volatile ComplianceConfig complianceConfig;

    private static final List<String> writeClasses = new ArrayList<>();
    {
        writeClasses.add(IndexRequest.class.getSimpleName());
        writeClasses.add(UpdateRequest.class.getSimpleName());
        writeClasses.add(BulkRequest.class.getSimpleName());
        writeClasses.add(BulkShardRequest.class.getSimpleName());
        writeClasses.add(DeleteRequest.class.getSimpleName());
    }

    protected AbstractAuditLog(Settings settings, final ThreadPool threadPool, final IndexNameExpressionResolver resolver, final ClusterService clusterService, final boolean dlsFlsAvailable) {
        super();
        this.threadPool = threadPool;
        this.settings = settings;
        this.resolver = resolver;
        this.clusterService = clusterService;
        this.auditConfigFilter = AuditConfig.Filter.from(settings);
        this.auditConfigFilter.log(log);
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        if (dlsFlsAvailable) {
            this.complianceConfig = ComplianceConfig.from(settings);
            this.complianceConfig.log(log);
        } else {
            this.complianceConfig = null;
            log.debug("Compliance config is null because DLS-FLS is not available.");
        }
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
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.FAILED_LOGIN, getOrigin(), action, null, effectiveUser, securityadmin, initiatingUser, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), opendistrosecurityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

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
        if(request != null && auditConfigFilter.shouldLogRequestBody() && request.hasContentOrSourceParam()) {
            msg.addTupleToRequestBody(request.contentOrSourceParam());
        }

        if(request != null) {
            msg.addPath(request.path());
            msg.addRestHeaders(request.getHeaders(), auditConfigFilter.shouldExcludeSensitiveHeaders());
            msg.addRestParams(request.params());
        }

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
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.AUTHENTICATED, getOrigin(), action, null, effectiveUser, securityadmin, initiatingUser,remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), opendistrosecurityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

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
        if(request != null && auditConfigFilter.shouldLogRequestBody() && request.hasContentOrSourceParam()) {
            msg.addTupleToRequestBody(request.contentOrSourceParam());
        }

        if(request != null) {
            msg.addPath(request.path());
            msg.addRestHeaders(request.getHeaders(), auditConfigFilter.shouldExcludeSensitiveHeaders());
            msg.addRestParams(request.params());
        }

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
        if(request != null && auditConfigFilter.shouldLogRequestBody() && request.hasContentOrSourceParam()) {
            msg.addTupleToRequestBody(request.contentOrSourceParam());
        }
        if(request != null) {
            msg.addPath(request.path());
            msg.addRestHeaders(request.getHeaders(), auditConfigFilter.shouldExcludeSensitiveHeaders());
            msg.addRestParams(request.params());
        }

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
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.MISSING_PRIVILEGES, getOrigin(), action, privilege, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), opendistrosecurityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

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
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.GRANTED_PRIVILEGES, getOrigin(), action, privilege, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), opendistrosecurityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

        for(AuditMessage msg: msgs) {
            save(msg);
        }
    }

    @Override
    public void logBadHeaders(TransportRequest request, String action, Task task) {

        if(!checkTransportFilter(AuditCategory.BAD_HEADERS, action, getUser(), request)) {
            return;
        }

        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.BAD_HEADERS, getOrigin(), action, null, getUser(), null, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), opendistrosecurityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

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
        if(request != null && auditConfigFilter.shouldLogRequestBody() && request.hasContentOrSourceParam()) {
            msg.addTupleToRequestBody(request.contentOrSourceParam());
        }
        if(request != null) {
            msg.addPath(request.path());
            msg.addRestHeaders(request.getHeaders(), auditConfigFilter.shouldExcludeSensitiveHeaders());
            msg.addRestParams(request.params());
        }

        msg.addEffectiveUser(getUser());

        save(msg);
    }

    @Override
    public void logSecurityIndexAttempt(TransportRequest request, String action, Task task) {

        if(!checkTransportFilter(AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT, action, getUser(), request)) {
            return;
        }

        final TransportAddress remoteAddress = getRemoteAddress();
        final List<AuditMessage> msgs = RequestResolver.resolve(AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT, getOrigin(), action, null, getUser(), false, null, remoteAddress, request, getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), opendistrosecurityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), null);

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
                getThreadContextHeaders(), task, resolver, clusterService, settings, auditConfigFilter.shouldLogRequestBody(), auditConfigFilter.shouldResolveIndices(), auditConfigFilter.shouldResolveBulkRequests(), opendistrosecurityIndex, auditConfigFilter.shouldExcludeSensitiveHeaders(), t);

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
        if(request != null && auditConfigFilter.shouldLogRequestBody() && request.hasContentOrSourceParam()) {
            msg.addTupleToRequestBody(request.contentOrSourceParam());
        }

        if(request != null) {
            msg.addPath(request.path());
            msg.addRestHeaders(request.getHeaders(), auditConfigFilter.shouldExcludeSensitiveHeaders());
            msg.addRestParams(request.params());
        }
        msg.addException(t);
        msg.addEffectiveUser(getUser());
        save(msg);
    }

    @Override
    public void logDocumentRead(String index, String id, ShardId shardId, Map<String, String> fieldNameValues) {

        if(complianceConfig == null || !complianceConfig.readHistoryEnabledForIndex(index)) {
            return;
        }

        final String initiatingRequestClass = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER);

        if(initiatingRequestClass != null && writeClasses.contains(initiatingRequestClass)) {
            return;
        }

        AuditCategory category = opendistrosecurityIndex.equals(index)? AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ: AuditCategory.COMPLIANCE_DOC_READ;

        String effectiveUser = getUser();
        if(!checkComplianceFilter(category, effectiveUser, getOrigin())) {
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
                    if(opendistrosecurityIndex.equals(index) && !"tattr".equals(id)) {
                        try {
                            Map<String, String> map = fieldNameValues.entrySet().stream()
                                    .collect(Collectors.toMap(entry -> "id", entry -> new String(BaseEncoding.base64().decode(((Entry<String, String>) entry).getValue()), StandardCharsets.UTF_8)));
                            msg.addMapToRequestBody(Utils.convertJsonToxToStructuredMap(map.get("id")));
                        } catch (Exception e) {
                            msg.addMapToRequestBody(new HashMap<String, Object>(fieldNameValues));
                        }
                    } else {
                        msg.addMapToRequestBody(new HashMap<String, Object>(fieldNameValues));
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

        if(complianceConfig == null || !complianceConfig.writeHistoryEnabledForIndex(shardId.getIndexName())) {
            return;
        }

        AuditCategory category = opendistrosecurityIndex.equals(shardId.getIndexName())? AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE: AuditCategory.COMPLIANCE_DOC_WRITE;

        String effectiveUser = getUser();

        if(!checkComplianceFilter(category, effectiveUser, getOrigin())) {
            return;
        }

        AuditMessage msg = new AuditMessage(category, clusterService, getOrigin(), null);
        TransportAddress remoteAddress = getRemoteAddress();
        msg.addRemoteAddress(remoteAddress);
        msg.addEffectiveUser(effectiveUser);
        msg.addIndices(new String[]{shardId.getIndexName()});
        msg.addResolvedIndices(new String[]{shardId.getIndexName()});
        msg.addId(currentIndex.id());
        msg.addShardId(shardId);
        msg.addComplianceDocVersion(result.getVersion());
        msg.addComplianceOperation(result.isCreated()?Operation.CREATE:Operation.UPDATE);

        if(complianceConfig.shouldLogDiffsForWrite() && originalResult != null && originalResult.isExists() && originalResult.internalSourceRef() != null) {
            try {
                String originalSource = null;
                String currentSource = null;
                if (opendistrosecurityIndex.equals(shardId.getIndexName())) {
                    try (XContentParser parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, OpenDistroSecurityDeprecationHandler.INSTANCE, originalResult.internalSourceRef(), XContentType.JSON)) {
                        Object base64 = parser.map().values().iterator().next();
                        if(base64 instanceof String) {
                            originalSource = (new String(BaseEncoding.base64().decode((String) base64)));
                        } else {
                            originalSource = XContentHelper.convertToJson(originalResult.internalSourceRef(), false, XContentType.JSON);
                        }
                    } catch (Exception e) {
                        log.error(e);
                    }

                    try (XContentParser parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, OpenDistroSecurityDeprecationHandler.INSTANCE, currentIndex.source(), XContentType.JSON)) {
                        Object base64 = parser.map().values().iterator().next();
                        if(base64 instanceof String) {
                            currentSource = (new String(BaseEncoding.base64().decode((String) base64)));
                        } else {
                            currentSource = XContentHelper.convertToJson(currentIndex.source(), false, XContentType.JSON);
                        }
                    } catch (Exception e) {
                        log.error(e);
                    }
                } else {
                    originalSource = XContentHelper.convertToJson(originalResult.internalSourceRef(), false, XContentType.JSON);
                    currentSource = XContentHelper.convertToJson(currentIndex.source(), false, XContentType.JSON);
                }
                final JsonNode diffnode = JsonDiff.asJson(DefaultObjectMapper.objectMapper.readTree(originalSource), DefaultObjectMapper.objectMapper.readTree(currentSource));
                msg.addComplianceWriteDiffSource(diffnode.size() == 0?"":diffnode.toString());
            } catch (Exception e) {
                log.error("Unable to generate diff for {}",msg.toPrettyString(),e);
            }
        }


        if (!complianceConfig.shouldLogWriteMetadataOnly()){
            if(opendistrosecurityIndex.equals(shardId.getIndexName())) {
                //current source, normally not null or empty
                try (XContentParser parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, OpenDistroSecurityDeprecationHandler.INSTANCE, currentIndex.source(), XContentType.JSON)) {
                    Object base64 = parser.map().values().iterator().next();
                    if(base64 instanceof String) {
                        msg.addUnescapedJsonToRequestBody(new String(BaseEncoding.base64().decode((String) base64)));
                    } else {
                        msg.addTupleToRequestBody(new Tuple<XContentType, BytesReference>(XContentType.JSON, currentIndex.source()));
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

        if(!checkComplianceFilter(AuditCategory.COMPLIANCE_DOC_WRITE, effectiveUser, getOrigin())) {
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

    @Override
    public void logExternalConfig(Settings settings, Environment environment) {

        if(!checkComplianceFilter(AuditCategory.COMPLIANCE_EXTERNAL_CONFIG, null, getOrigin())) {
            return;
        }

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
            builder.field("elasticsearch_yml", configAsMap);
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

    private boolean checkTransportFilter(final AuditCategory category, final String action, final String effectiveUser, TransportRequest request) {

        if(log.isTraceEnabled()) {
            log.trace("Check category:{}, action:{}, effectiveUser:{}, request:{}", category, action, effectiveUser, request==null?null:request.getClass().getSimpleName());
        }


        if (!auditConfigFilter.isTransportApiAuditEnabled()) {
            //ignore for certain categories
            if(category != AuditCategory.FAILED_LOGIN
                    && category != AuditCategory.MISSING_PRIVILEGES
                    && category != AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT) {

                return false;
            }

        }

        //skip internals
        if(action != null
                &&
                ( action.startsWith("internal:")
                        || action.startsWith("cluster:monitor")
                        || action.startsWith("indices:monitor")
                )
        ) {


            //if(log.isTraceEnabled()) {
            //    log.trace("Skipped audit log message due to category ({}) or action ({}) does not match", category, action);
            //}

            return false;
        }

        if (auditConfigFilter.isAuditDisabled(effectiveUser)) {

            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because of user {} is ignored", effectiveUser);
            }

            return false;
        }

        if (request != null && (auditConfigFilter.isRequestAuditDisabled(action) || auditConfigFilter.isRequestAuditDisabled(request.getClass().getSimpleName()))) {

            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because request {} is ignored", action+"#"+request.getClass().getSimpleName());
            }

            return false;
        }

        if (!auditConfigFilter.getDisabledTransportCategories().contains(category)) {
            return true;
        } else {
            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because category {} not enabled", category);
            }
            return false;
        }


        //skip cluster:monitor, index:monitor, internal:*
        //check transport audit enabled
        //check category enabled
        //check action
        //check ignoreAuditUsers

    }

    private boolean checkComplianceFilter(final AuditCategory category, final String effectiveUser, Origin origin) {
        if(log.isTraceEnabled()) {
            log.trace("Check for COMPLIANCE category:{}, effectiveUser:{}, origin: {}", category, effectiveUser, origin);
        }

        if(origin == Origin.LOCAL && effectiveUser == null && category != AuditCategory.COMPLIANCE_EXTERNAL_CONFIG) {
            if(log.isTraceEnabled()) {
                log.trace("Skipped compliance log message because of null user and local origin");
            }
            return false;
        }

        if(category == AuditCategory.COMPLIANCE_DOC_READ || category == AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ) {

            if (effectiveUser != null && auditConfigFilter.isComplianceReadAuditDisabled(effectiveUser)) {

                if(log.isTraceEnabled()) {
                    log.trace("Skipped compliance log message because of user {} is ignored", effectiveUser);
                }
                return false;
            }
        }

        if(category == AuditCategory.COMPLIANCE_DOC_WRITE || category == AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE) {
            if (effectiveUser != null && auditConfigFilter.isComplianceWriteAuditDisabled(effectiveUser)) {

                if(log.isTraceEnabled()) {
                    log.trace("Skipped compliance log message because of user {} is ignored", effectiveUser);
                }
                return false;
            }
        }

        return true;
    }


    private boolean checkRestFilter(final AuditCategory category, final String effectiveUser, RestRequest request) {
        if(log.isTraceEnabled()) {
            log.trace("Check for REST category:{}, effectiveUser:{}, request:{}", category, effectiveUser, request==null?null:request.path());
        }

        if (!auditConfigFilter.isRestApiAuditEnabled()) {
            //ignore for certain categories
            if(category != AuditCategory.FAILED_LOGIN
                    && category != AuditCategory.MISSING_PRIVILEGES
                    && category != AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT) {

                return false;
            }

        }

        if (auditConfigFilter.isAuditDisabled(effectiveUser)) {

            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because of user {} is ignored", effectiveUser);
            }

            return false;
        }

        if (request != null && auditConfigFilter.isRequestAuditDisabled(request.path())) {

            if(log.isTraceEnabled()) {
                log.trace("Skipped audit log message because request {} is ignored", request.path());
            }

            return false;
        }

        if (!auditConfigFilter.getDisabledRestCategories().contains(category)) {
            return true;
        } else {
            if(log.isTraceEnabled()) {
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
