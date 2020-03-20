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
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog.Operation;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog.Origin;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;

public final class AuditMessage {

    //clustername and cluster uuid
    private static final String AUTHORIZATION_HEADER = "Authorization";
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
    //public static final String REST_REQUEST_BODY = "audit_rest_request_body";
    public static final String REST_REQUEST_PARAMS = "audit_rest_request_params";
    public static final String REST_REQUEST_HEADERS = "audit_rest_request_headers";

    public static final String TRANSPORT_REQUEST_TYPE = "audit_transport_request_type";
    public static final String TRANSPORT_ACTION = "audit_transport_action";
    public static final String TRANSPORT_REQUEST_HEADERS = "audit_transport_headers";

    public static final String ID = "audit_trace_doc_id";
    //public static final String TYPES = "audit_trace_doc_types";
    //public static final String SOURCE = "audit_trace_doc_source";
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

    //public static final String COMPLIANCE_DIFF_STORED_IS_NOOP = "audit_compliance_diff_stored_is_noop";
    //public static final String COMPLIANCE_STORED_FIELDS_CONTENT = "audit_compliance_stored_fields_content";

    public static final String REQUEST_LAYER = "audit_request_layer";

    public static final String COMPLIANCE_OPERATION = "audit_compliance_operation";
    public static final String COMPLIANCE_DOC_VERSION = "audit_compliance_doc_version";

    private static final DateTimeFormatter DEFAULT_FORMAT = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZZ");
    private final Map<String, Object> auditInfo = new HashMap<String, Object>(50);
    private final AuditCategory msgCategory;

    public AuditMessage(final AuditCategory msgCategory, final ClusterService clusterService, final Origin origin, final Origin layer) {
        this.msgCategory = Objects.requireNonNull(msgCategory);
        final String currentTime = currentTime();
        auditInfo.put(FORMAT_VERSION, 4);
        auditInfo.put(CATEGORY, Objects.requireNonNull(msgCategory));
        auditInfo.put(UTC_TIMESTAMP, currentTime);
        auditInfo.put(NODE_HOST_ADDRESS, Objects.requireNonNull(clusterService).localNode().getHostAddress());
        auditInfo.put(NODE_ID, Objects.requireNonNull(clusterService).localNode().getId());
        auditInfo.put(NODE_HOST_NAME, Objects.requireNonNull(clusterService).localNode().getHostName());
        auditInfo.put(NODE_NAME, Objects.requireNonNull(clusterService).localNode().getName());
        auditInfo.put(CLUSTER_NAME, Objects.requireNonNull(clusterService).getClusterName().value());

        if(origin != null) {
            auditInfo.put(ORIGIN, origin);
        }

        if(layer != null) {
            auditInfo.put(REQUEST_LAYER, layer);
        }
    }

    public void addRemoteAddress(TransportAddress remoteAddress) {
        if (remoteAddress != null && remoteAddress.getAddress() != null) {
            auditInfo.put(REMOTE_ADDRESS, remoteAddress.getAddress());
        }
    }

    public void addIsAdminDn(boolean isAdminDn) {
        auditInfo.put(IS_ADMIN_DN, isAdminDn);
    }

    public void addException(Throwable t) {
        if (t != null) {
            auditInfo.put(EXCEPTION, ExceptionsHelper.stackTrace(t));
        }
    }

    public void addPrivilege(String priv) {
        if (priv != null) {
            auditInfo.put(PRIVILEGE, priv);
        }
    }

    public void addInitiatingUser(String user) {
        if (user != null) {
            auditInfo.put(REQUEST_INITIATING_USER, user);
        }
    }

    public void addEffectiveUser(String user) {
        if (user != null) {
            auditInfo.put(REQUEST_EFFECTIVE_USER, user);
        }
    }

    public void addPath(String path) {
        if (path != null) {
            auditInfo.put(REST_REQUEST_PATH, path);
        }
    }

    public void addComplianceWriteDiffSource(String diff) {
        if (diff != null && !diff.isEmpty()) {
            auditInfo.put(COMPLIANCE_DIFF_CONTENT, diff);
            auditInfo.put(COMPLIANCE_DIFF_IS_NOOP, false);
        } else if (diff != null && diff.isEmpty()) {
            auditInfo.put(COMPLIANCE_DIFF_IS_NOOP, true);
        }
    }

//    public void addComplianceWriteStoredFields0(String diff) {
//        if (diff != null && !diff.isEmpty()) {
//            auditInfo.put(COMPLIANCE_STORED_FIELDS_CONTENT, diff);
//            //auditInfo.put(COMPLIANCE_DIFF_STORED_IS_NOOP, false);
//        }
//    }

    public void addTupleToRequestBody(Tuple<XContentType, BytesReference> xContentTuple) {
        if (xContentTuple != null) {
            try {
                auditInfo.put(REQUEST_BODY, XContentHelper.convertToJson(xContentTuple.v2(), false, xContentTuple.v1()));
            } catch (Exception e) {
                auditInfo.put(REQUEST_BODY, "ERROR: Unable to convert to json because of "+e.toString());
            }
        }
    }

    public void addMapToRequestBody(Map<String, Object> map) {
        if(map != null) {
            auditInfo.put(REQUEST_BODY, Utils.convertStructuredMapToJson(map));
        }
    }

    public void addUnescapedJsonToRequestBody(String source) {
        if (source != null) {
            auditInfo.put(REQUEST_BODY, source);
        }
    }

    public void addRequestType(String requestType) {
        if (requestType != null) {
            auditInfo.put(TRANSPORT_REQUEST_TYPE, requestType);
        }
    }

    public void addAction(String action) {
        if (action != null) {
            auditInfo.put(TRANSPORT_ACTION, action);
        }
    }

    public void addId(String id) {
        if (id != null) {
            auditInfo.put(ID, id);
        }
    }

    /*public void addTypes(String[] types) {
        if (types != null && types.length > 0) {
            auditInfo.put(TYPES, types);
        }
    }

    public void addType(String type) {
        if (type != null) {
            auditInfo.put(TYPES, new String[] { type });
        }
    }*/

    public void addFileInfos(Map<String, Path> paths) {
        if (paths != null && !paths.isEmpty()) {
            List<Object> infos = new ArrayList<>();
            for(Entry<String, Path> path: paths.entrySet()) {

                try {
                    if(Files.isReadable(path.getValue())) {
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
    }

    /*public void addSource(Map<String, String> source) {
        if (source != null && !source.isEmpty()) {
            auditInfo.put(REQUEST_BODY, source);
        }
    }*/

    public void addIndices(String[] indices) {
        if (indices != null && indices.length > 0) {
            auditInfo.put(INDICES, indices);
        }

    }

    public void addResolvedIndices(String[] resolvedIndices) {
        if (resolvedIndices != null && resolvedIndices.length > 0) {
            auditInfo.put(RESOLVED_INDICES, resolvedIndices);
        }
    }

    public void addTaskId(long id) {
         auditInfo.put(TASK_ID, auditInfo.get(NODE_ID)+":"+id);
    }

    public void addShardId(ShardId id) {
        if(id != null) {
            auditInfo.put(SHARD_ID, id.getId());
        }
   }

    public void addTaskParentId(String id) {
        if(id != null) {
            auditInfo.put(TASK_PARENT_ID, id);
        }
    }

    public void addRestParams(Map<String,String> params) {
        if(params != null && !params.isEmpty()) {
            auditInfo.put(REST_REQUEST_PARAMS, new HashMap<>(params));
        }
    }

    public void addRestHeaders(Map<String,List<String>> headers, boolean excludeSensitiveHeaders) {
        if(headers != null && !headers.isEmpty()) {
            if(excludeSensitiveHeaders) {
                final Map<String, List<String>> headersClone = new HashMap<String, List<String>>(headers)
                        .entrySet().stream()
                        .filter(map -> !map.getKey().equalsIgnoreCase(AUTHORIZATION_HEADER))
                        .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));
                auditInfo.put(REST_REQUEST_HEADERS, headersClone);
            } else {
                auditInfo.put(REST_REQUEST_HEADERS, new HashMap<String, List<String>>(headers));
            }
        }
    }

    public void addTransportHeaders(Map<String,String> headers, boolean excludeSensitiveHeaders) {
        if(headers != null && !headers.isEmpty()) {
            if(excludeSensitiveHeaders) {
                final Map<String,String> headersClone = new HashMap<String,String>(headers)
                        .entrySet().stream()
                        .filter(map -> !map.getKey().equalsIgnoreCase(AUTHORIZATION_HEADER))
                        .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));
                auditInfo.put(TRANSPORT_REQUEST_HEADERS, headersClone);
            } else {
                auditInfo.put(TRANSPORT_REQUEST_HEADERS, new HashMap<String,String>(headers));
            }
        }
    }

    public void addComplianceOperation(Operation op) {
        if(op != null) {
            auditInfo.put(COMPLIANCE_OPERATION, op);
        }
    }

    public void addComplianceDocVersion(long version) {
        auditInfo.put(COMPLIANCE_DOC_VERSION, version);
    }

    public Map<String, Object> getAsMap() {
      return new HashMap<>(this.auditInfo);
    }

    public String getInitiatingUser() {
        return (String) this.auditInfo.get(REQUEST_INITIATING_USER);
    }

    public String getEffectiveUser() {
        return (String) this.auditInfo.get(REQUEST_EFFECTIVE_USER);
    }

    public String getRequestType() {
        return (String) this.auditInfo.get(TRANSPORT_REQUEST_TYPE);
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

    private String currentTime() {
        DateTime dt = new DateTime(DateTimeZone.UTC);
        return DEFAULT_FORMAT.print(dt);
    }

    private String formatTime(long epoch) {
        DateTime dt = new DateTime(epoch, DateTimeZone.UTC);
        return DEFAULT_FORMAT.print(dt);
    }

    protected String stringOrNull(Object object) {
        if(object == null) {
            return null;
        }

        return String.valueOf(object);
    }
}
