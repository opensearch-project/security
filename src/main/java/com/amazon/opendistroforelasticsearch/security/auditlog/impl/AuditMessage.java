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

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.client.utils.URIBuilder;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.rest.RestRequest;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.stream.Collectors;

public final class AuditMessage {

    private final Map<String, Object> auditInfo;
    private final AuditCategory msgCategory;

    public AuditMessage(final AuditCategory msgCategory, final Map<String, Object> auditInfo) {
        this.msgCategory = Objects.requireNonNull(msgCategory);
        this.auditInfo = auditInfo;
    }

    public Map<String, Object> getAsMap() {
        return new HashMap<>(this.auditInfo);
    }

    public AuditCategory getCategory() {
        return msgCategory;
    }

    @Override
    public String toString() {
        try {
            return Strings.toString(JsonXContent.contentBuilder().map(getAsMap()));
        } catch (final IOException e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

    public String toPrettyString() {
        try {
            return Strings.toString(JsonXContent.contentBuilder().prettyPrint().map(getAsMap()));
        } catch (final IOException e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

    public String toText() {
        StringBuilder builder = new StringBuilder();
        for (Entry<String, Object> entry : getAsMap().entrySet()) {
            addIfNonEmpty(builder, entry.getKey(), stringOrNull(entry.getValue()));
        }
        return builder.toString();
    }

    public final String toJson() {
        return this.toString();
    }

    public String toUrlParameters() {
        URIBuilder builder = new URIBuilder();
        for (Entry<String, Object> entry : getAsMap().entrySet()) {
            builder.addParameter(entry.getKey(), stringOrNull(entry.getValue()));
        }
        return builder.toString();
    }

    protected static void addIfNonEmpty(StringBuilder builder, String key, String value) {
        if (!Strings.isEmpty(value)) {
            if (builder.length() > 0) {
                builder.append("\n");
            }
            builder.append(key).append(": ").append(value);
        }
    }

    protected String stringOrNull(Object object) {
        if (object == null) {
            return null;
        }
        return String.valueOf(object);
    }

    public static class Builder {
        public static final String FORMAT_VERSION = "audit_format_version";
        public static final String CATEGORY = "audit_category";
        public static final String REQUEST_EFFECTIVE_USER = "audit_request_effective_user";
        public static final String REQUEST_INITIATING_USER = "audit_request_initiating_user";
        public static final String UTC_TIMESTAMP = "@timestamp";
        public static final String CLUSTER_NAME = "audit_cluster_name";
        public static final String NODE_ID = "audit_node_id";
        public static final String NODE_HOST_ADDRESS = "audit_node_host_address";
        public static final String NODE_HOST_NAME = "audit_node_host_name";
        public static final String NODE_NAME = "audit_node_name";
        public static final String ORIGIN = "audit_request_origin";
        public static final String REMOTE_ADDRESS = "audit_request_remote_address";
        public static final String REST_REQUEST_PATH = "audit_rest_request_path";
        public static final String REST_REQUEST_PARAMS = "audit_rest_request_params";
        public static final String REST_REQUEST_HEADERS = "audit_rest_request_headers";
        public static final String TRANSPORT_REQUEST_TYPE = "audit_transport_request_type";
        public static final String TRANSPORT_ACTION = "audit_transport_action";
        public static final String TRANSPORT_REQUEST_HEADERS = "audit_transport_headers";
        public static final String ID = "audit_trace_doc_id";
        public static final String INDICES = "audit_trace_indices";
        public static final String SHARD_ID = "audit_trace_shard_id";
        public static final String RESOLVED_INDICES = "audit_trace_resolved_indices";
        public static final String EXCEPTION = "audit_request_exception_stacktrace";
        public static final String IS_ADMIN_DN = "audit_request_effective_user_is_admin";
        public static final String PRIVILEGE = "audit_request_privilege";
        public static final String TASK_ID = "audit_trace_task_id";
        public static final String TASK_PARENT_ID = "audit_trace_task_parent_id";
        public static final String REQUEST_BODY = "audit_request_body";
        public static final String COMPLIANCE_DIFF_IS_NOOP = "audit_compliance_diff_is_noop";
        public static final String COMPLIANCE_DIFF_CONTENT = "audit_compliance_diff_content";
        public static final String COMPLIANCE_FILE_INFOS = "audit_compliance_file_infos";
        public static final String REQUEST_LAYER = "audit_request_layer";
        public static final String COMPLIANCE_OPERATION = "audit_compliance_operation";
        public static final String COMPLIANCE_DOC_VERSION = "audit_compliance_doc_version";
        //clustername and cluster uuid
        private static final String AUTHORIZATION_HEADER = "Authorization";
        private static final DateTimeFormatter DEFAULT_FORMAT = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZZ");

        private final Map<String, Object> auditInfo;
        private AuditCategory category;

        public Builder(final AuditCategory category) {
            this.auditInfo = new HashMap<>(50);
            this.category = category;
            auditInfo.put(CATEGORY, Objects.requireNonNull(category));
            auditInfo.put(FORMAT_VERSION, 4);
            auditInfo.put(UTC_TIMESTAMP, currentTime());
        }

        public AuditMessage build() {
            return new AuditMessage(category, auditInfo);
        }

        public Builder addOrigin(final AuditLog.Origin origin) {
            if (origin != null) {
                auditInfo.put(ORIGIN, origin);
            }
            return this;
        }

        public Builder addClusterServiceInfo(final ClusterService clusterService) {
            if (clusterService != null) {
                auditInfo.put(NODE_HOST_ADDRESS, Objects.requireNonNull(clusterService).localNode().getHostAddress());
                auditInfo.put(NODE_ID, Objects.requireNonNull(clusterService).localNode().getId());
                auditInfo.put(NODE_HOST_NAME, Objects.requireNonNull(clusterService).localNode().getHostName());
                auditInfo.put(NODE_NAME, Objects.requireNonNull(clusterService).localNode().getName());
                auditInfo.put(CLUSTER_NAME, Objects.requireNonNull(clusterService).getClusterName().value());
            }
            return this;
        }

        public Builder addLayer(final AuditLog.Origin layer) {
            if (layer != null) {
                auditInfo.put(REQUEST_LAYER, layer);
            }
            return this;
        }

        public Builder addRemoteAddress(final TransportAddress remoteAddress) {
            if (remoteAddress != null && remoteAddress.getAddress() != null) {
                auditInfo.put(REMOTE_ADDRESS, remoteAddress.getAddress());
            }
            return this;
        }

        public Builder addIsAdminDn(boolean isAdminDn) {
            auditInfo.put(IS_ADMIN_DN, isAdminDn);
            return this;
        }

        public Builder addException(final Throwable t) {
            if (t != null) {
                auditInfo.put(EXCEPTION, ExceptionsHelper.stackTrace(t));
            }
            return this;
        }

        public Builder addPrivilege(final String priv) {
            if (priv != null) {
                auditInfo.put(PRIVILEGE, priv);
            }
            return this;
        }

        public Builder addInitiatingUser(final String user) {
            if (user != null) {
                auditInfo.put(REQUEST_INITIATING_USER, user);
            }
            return this;
        }

        public Builder addEffectiveUser(final String user) {
            if (user != null) {
                auditInfo.put(REQUEST_EFFECTIVE_USER, user);
            }
            return this;
        }

        public Builder addPath(final String path) {
            if (path != null) {
                auditInfo.put(REST_REQUEST_PATH, path);
            }
            return this;
        }

        public Builder addComplianceWriteDiffSource(final String diff) {
            if (diff != null && !diff.isEmpty()) {
                auditInfo.put(COMPLIANCE_DIFF_CONTENT, diff);
                auditInfo.put(COMPLIANCE_DIFF_IS_NOOP, false);
            } else if (diff != null && diff.isEmpty()) {
                auditInfo.put(COMPLIANCE_DIFF_IS_NOOP, true);
            }
            return this;
        }

        public Builder addTupleToRequestBody(final Tuple<XContentType, BytesReference> xContentTuple) {
            if (xContentTuple != null) {
                try {
                    auditInfo.put(REQUEST_BODY, XContentHelper.convertToJson(xContentTuple.v2(), false, xContentTuple.v1()));
                } catch (Exception e) {
                    auditInfo.put(REQUEST_BODY, "ERROR: Unable to convert to json because of " + e.toString());
                }
            }
            return this;
        }

        public Builder addMapToRequestBody(final Map<String, Object> map) {
            if (map != null) {
                auditInfo.put(REQUEST_BODY, Utils.convertStructuredMapToJson(map));
            }
            return this;
        }

        public Builder addUnescapedJsonToRequestBody(final String source) {
            if (source != null) {
                auditInfo.put(REQUEST_BODY, source);
            }
            return this;
        }

        public Builder addRequestType(final String requestType) {
            if (requestType != null) {
                auditInfo.put(TRANSPORT_REQUEST_TYPE, requestType);
            }
            return this;
        }

        public Builder addAction(final String action) {
            if (action != null) {
                auditInfo.put(TRANSPORT_ACTION, action);
            }
            return this;
        }

        public Builder addId(final String id) {
            if (id != null) {
                auditInfo.put(ID, id);
            }
            return this;
        }

        public Builder addIndices(final String[] indices) {
            if (indices != null && indices.length > 0) {
                auditInfo.put(INDICES, indices);
            }
            return this;
        }

        public Builder addResolvedIndices(final String[] resolvedIndices) {
            if (resolvedIndices != null && resolvedIndices.length > 0) {
                auditInfo.put(RESOLVED_INDICES, resolvedIndices);
            }
            return this;
        }

        public Builder addTaskId(final long id) {
            auditInfo.put(TASK_ID, auditInfo.get(NODE_ID) + ":" + id);
            return this;
        }

        public Builder addShardId(final ShardId id) {
            if (id != null) {
                auditInfo.put(SHARD_ID, id.getId());
            }
            return this;
        }

        public Builder addTaskParentId(final String id) {
            if (id != null) {
                auditInfo.put(TASK_PARENT_ID, id);
            }
            return this;
        }

        public Builder addRestParams(final Map<String, String> params) {
            if (params != null && !params.isEmpty()) {
                auditInfo.put(REST_REQUEST_PARAMS, new HashMap<>(params));
            }
            return this;
        }

        public Builder addRestHeaders(final Map<String, List<String>> headers, boolean excludeSensitiveHeaders) {
            if (headers != null && !headers.isEmpty()) {
                if (excludeSensitiveHeaders) {
                    final Map<String, List<String>> headersClone = new HashMap<String, List<String>>(headers)
                            .entrySet().stream()
                            .filter(map -> !map.getKey().equalsIgnoreCase(AUTHORIZATION_HEADER))
                            .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));
                    auditInfo.put(REST_REQUEST_HEADERS, headersClone);
                } else {
                    auditInfo.put(REST_REQUEST_HEADERS, new HashMap<String, List<String>>(headers));
                }
            }
            return this;
        }

        public Builder addTransportHeaders(final Map<String, String> headers, boolean excludeSensitiveHeaders) {
            if (headers != null && !headers.isEmpty()) {
                if (excludeSensitiveHeaders) {
                    final Map<String, String> headersClone = new HashMap<String, String>(headers)
                            .entrySet().stream()
                            .filter(map -> !map.getKey().equalsIgnoreCase(AUTHORIZATION_HEADER))
                            .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));
                    auditInfo.put(TRANSPORT_REQUEST_HEADERS, headersClone);
                } else {
                    auditInfo.put(TRANSPORT_REQUEST_HEADERS, new HashMap<String, String>(headers));
                }
            }
            return this;
        }

        public Builder addComplianceOperation(final AuditLog.Operation op) {
            if (op != null) {
                auditInfo.put(COMPLIANCE_OPERATION, op);
            }
            return this;
        }

        public Builder addComplianceDocVersion(long version) {
            auditInfo.put(COMPLIANCE_DOC_VERSION, version);
            return this;
        }

        public Builder addRequestInfo(final RestRequest request, boolean excludeSensitiveHeaders) {
            if (request != null) {
                addPath(request.path());
                addRestHeaders(request.getHeaders(), excludeSensitiveHeaders);
                addRestParams(request.params());
            }

            return this;
        }

        public Builder addRequestBody(final RestRequest request, boolean logRequestBody) {
            if (request != null && logRequestBody && request.hasContentOrSourceParam()) {
                addTupleToRequestBody(request.contentOrSourceParam());
            }

            return this;
        }

        public Builder addFileInfos(final Map<String, Path> paths) {
            if (paths != null && !paths.isEmpty()) {
                List<Object> infos = new ArrayList<>();
                for (Entry<String, Path> path : paths.entrySet()) {

                    try {
                        if (Files.isReadable(path.getValue())) {
                            final String chcksm = DigestUtils.sha256Hex(Files.readAllBytes(path.getValue()));
                            FileTime lm = Files.getLastModifiedTime(path.getValue(), LinkOption.NOFOLLOW_LINKS);
                            Map<String, Object> innerInfos = new HashMap<>();
                            innerInfos.put("sha256", chcksm);
                            innerInfos.put("last_modified", formatTime(lm.toMillis()));
                            innerInfos.put("key", path.getKey());
                            innerInfos.put("path", path.getValue().toAbsolutePath().toString());
                            infos.add(innerInfos);
                        }
                    } catch (Throwable e) {
                        //ignore non readable files
                    }
                }
                auditInfo.put(COMPLIANCE_FILE_INFOS, infos);
            }
            return this;
        }

        private String formatTime(long epoch) {
            DateTime dt = new DateTime(epoch, DateTimeZone.UTC);
            return DEFAULT_FORMAT.print(dt);
        }

        private String currentTime() {
            DateTime dt = new DateTime(DateTimeZone.UTC);
            return DEFAULT_FORMAT.print(dt);
        }
    }
}
