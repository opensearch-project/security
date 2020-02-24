package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityDeprecationHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.flipkart.zjsonpatch.JsonDiff;
import com.google.common.io.BaseEncoding;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.engine.Engine.Index;
import org.elasticsearch.index.engine.Engine.IndexResult;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.shard.ShardId;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class ComplianceResolver {

    private final Logger log = LogManager.getLogger(this.getClass());
    private ClusterService clusterService;
    private IndexNameExpressionResolver indexNameExpressionResolver;
    private String opendistrosecurityIndex;

    public ComplianceResolver(
            final ClusterService clusterService,
            final IndexNameExpressionResolver indexNameExpressionResolver,
            final String opendistrosecurityIndex) {
        this.clusterService = clusterService;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.opendistrosecurityIndex = opendistrosecurityIndex;
    }

    public AuditMessage resolve(final AuditLog.Origin origin,
                                final TransportAddress remoteAddress,
                                final String index,
                                final String id,
                                final ShardId shardId,
                                final Map<String, String> fieldNameValues,
                                final String effectiveUser,
                                final AuditConfig auditConfig) {
        AuditCategory category = opendistrosecurityIndex.equals(index) ? AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ : AuditCategory.COMPLIANCE_DOC_READ;

        AuditMessage.Builder auditMessageBuilder = new AuditMessage.Builder(category)
                .addClusterServiceInfo(clusterService)
                .addOrigin(origin)
                .addRemoteAddress(remoteAddress)
                .addEffectiveUser(effectiveUser)
                .addIndices(new String[]{index})
                .addResolvedIndices(new String[]{index})
                .addShardId(shardId)
                .addId(id);

        try {
            if (auditConfig.shouldLogReadMetadataOnly()) {
                try {
                    XContentBuilder builder = XContentBuilder.builder(JsonXContent.jsonXContent);
                    builder.startObject()
                            .field("field_names", fieldNameValues.keySet())
                            .endObject()
                            .close();
                    auditMessageBuilder.addUnescapedJsonToRequestBody(Strings.toString(builder));
                } catch (IOException e) {
                    log.error(e.toString(), e);
                }
            } else {
                if (opendistrosecurityIndex.equals(index) && !"tattr".equals(id)) {
                    try {
                        Map<String, String> map = fieldNameValues.entrySet()
                                .stream()
                                .collect(Collectors.toMap(entry -> "id", entry -> new String(BaseEncoding.base64().decode(entry.getValue()), StandardCharsets.UTF_8)));
                        auditMessageBuilder.addMapToRequestBody(Utils.convertJsonToxToStructuredMap(map.get("id")));
                    } catch (Exception e) {
                        auditMessageBuilder.addMapToRequestBody(new HashMap<>(fieldNameValues));
                    }
                } else {
                    auditMessageBuilder.addMapToRequestBody(new HashMap<>(fieldNameValues));
                }
            }
        } catch (Exception e) {
            log.error("Unable to generate request body for {}", fieldNameValues, e.getMessage());
        }
        return auditMessageBuilder.build();
    }

    public AuditMessage resolve(final AuditLog.Origin origin,
                                final TransportAddress remoteAddress,
                                final ShardId shardId,
                                final GetResult originalResult,
                                final Index currentIndex,
                                final IndexResult result,
                                final String effectiveUser,
                                final AuditConfig auditConfig) {

        AuditCategory category = opendistrosecurityIndex.equals(shardId.getIndexName()) ? AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE : AuditCategory.COMPLIANCE_DOC_WRITE;

        AuditMessage.Builder auditMessageBuilder = new AuditMessage.Builder(category)
                .addClusterServiceInfo(clusterService)
                .addOrigin(origin)
                .addRemoteAddress(remoteAddress)
                .addEffectiveUser(effectiveUser)
                .addShardId(shardId)
                .addEffectiveUser(effectiveUser)
                .addIndices(new String[]{shardId.getIndexName()})
                .addResolvedIndices(new String[]{shardId.getIndexName()})
                .addId(currentIndex.id())
                .addShardId(shardId)
                .addComplianceDocVersion(result.getVersion())
                .addComplianceOperation(result.isCreated() ? AuditLog.Operation.CREATE : AuditLog.Operation.UPDATE);

        if (auditConfig.shouldLogDiffsForWrite() && originalResult != null && originalResult.isExists() && originalResult.internalSourceRef() != null) {
            try {
                String originalSource = null;
                String currentSource = null;
                if (opendistrosecurityIndex.equals(shardId.getIndexName())) {
                    try (XContentParser parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, OpenDistroSecurityDeprecationHandler.INSTANCE, originalResult.internalSourceRef(), XContentType.JSON)) {
                        Object base64 = parser.map().values().iterator().next();
                        if (base64 instanceof String) {
                            originalSource = (new String(BaseEncoding.base64().decode((String) base64)));
                        } else {
                            originalSource = XContentHelper.convertToJson(originalResult.internalSourceRef(), false, XContentType.JSON);
                        }
                    } catch (Exception e) {
                        log.error(e);
                    }

                    try (XContentParser parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, OpenDistroSecurityDeprecationHandler.INSTANCE, currentIndex.source(), XContentType.JSON)) {
                        Object base64 = parser.map().values().iterator().next();
                        if (base64 instanceof String) {
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
                auditMessageBuilder.addComplianceWriteDiffSource(diffnode.size() == 0 ? "" : diffnode.toString());
            } catch (Exception e) {
                log.error("Unable to generate diff", e);
            }
        }

        if (!auditConfig.shouldLogWriteMetadataOnly()) {
            if (opendistrosecurityIndex.equals(shardId.getIndexName())) {
                //current source, normally not null or empty
                try (XContentParser parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, OpenDistroSecurityDeprecationHandler.INSTANCE, currentIndex.source(), XContentType.JSON)) {
                    Object base64 = parser.map().values().iterator().next();
                    if (base64 instanceof String) {
                        auditMessageBuilder.addUnescapedJsonToRequestBody(new String(BaseEncoding.base64().decode((String) base64)));
                    } else {
                        auditMessageBuilder.addTupleToRequestBody(new Tuple<>(XContentType.JSON, currentIndex.source()));
                    }
                } catch (Exception e) {
                    log.error(e);
                }
                //if we want to have msg.ComplianceWritePreviousSource we need to do the same as above
            } else {
                //previous source, can be null if document is a new one
                //msg.ComplianceWritePreviousSource(new Tuple<XContentType, BytesReference>(XContentType.JSON, originalResult.internalSourceRef()));

                //current source, normally not null or empty
                auditMessageBuilder.addTupleToRequestBody(new Tuple<>(XContentType.JSON, currentIndex.source()));
            }
        }

        return auditMessageBuilder.build();
    }
}

