/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AuditLogValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.http.HttpRequest;
import org.elasticsearch.http.HttpResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.net.HttpHeaders;

public class AuditLogApiAction extends AbstractApiAction {
    private static final List<Route> routes = Collections.singletonList(
            new Route(RestRequest.Method.POST, "/_opendistro/_security/api/_auditlog")
    );

    static class AuditLogApiRequestContent {
        public AuditLogApiRequestContent(AuditCategory auditCategory, String effectiveUser, String privilege, Map<String, List<String>> headers, String remoteAddress) {
            this.auditCategory = auditCategory;
            this.effectiveUser = effectiveUser;
            this.privilege = privilege;
            this.headers = headers;
            this.remoteAddress = remoteAddress;
        }

        private AuditLogApiRequestContent() {
            this(null, null, null, null, null);
        }
        @JsonProperty("category")
        private final AuditCategory auditCategory;
        @JsonProperty("user")
        private final String effectiveUser;
        @JsonProperty("privilege")
        private final String privilege;
        @JsonProperty("headers")
        private final Map<String, List<String>> headers;
        @JsonProperty("remote")
        private final String remoteAddress;
    }

    private static class AuditLogHttpRequest implements HttpRequest {
        private String uri = "";
        private Map<String, List<String>> headers;
        BytesArray content = BytesArray.EMPTY;

        AuditLogHttpRequest(Map<String, List<String>> headers) {
            if (headers == null) {
                this.headers = ImmutableMap.of(HttpHeaders.CONTENT_TYPE, null);
            } else {
                this.headers = headers;
            }
        }

        @Override
        public Method method() {
            return null;
        }

        @Override
        public String uri() {
            return uri;
        }

        @Override
        public BytesReference content() {
            return content;
        }

        @Override
        public Map<String, List<String>> getHeaders() {
            return headers;
        }

        @Override
        public List<String> strictCookies() {
            return null;
        }

        @Override
        public HttpVersion protocolVersion() {
            return null;
        }

        @Override
        public HttpRequest removeHeader(String header) {
            return null;
        }

        @Override
        public HttpResponse createResponse(RestStatus status, BytesReference content) {
            return null;
        }

        @Override
        public void release() {

        }

        @Override
        public HttpRequest releaseAndCopy() {
            return null;
        }
    }

    private static class AuditLogHttpChannel implements HttpChannel {
        @Override
        public void sendResponse(HttpResponse response, ActionListener<Void> listener) {

        }

        @Override
        public InetSocketAddress getLocalAddress() {
            return null;
        }

        @Override
        public InetSocketAddress getRemoteAddress() {
            return null;
        }

        @Override
        public void close() {

        }

        @Override
        public void addCloseListener(ActionListener<Void> listener) {

        }

        @Override
        public boolean isOpen() {
            return false;
        }
    }

    public AuditLogApiAction(Settings settings, Path configPath, RestController controller, Client client, AdminDNs adminDNs,
                             ConfigurationRepository configurationRepository, ClusterService clusterService, PrincipalExtractor principalExtractor,
                             PrivilegesEvaluator privilegesEvaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, configurationRepository, clusterService, principalExtractor, privilegesEvaluator, threadPool, auditLog);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected void handleApiRequest(RestChannel channel, RestRequest request, Client client) throws IOException {
        if (!isSuperAdmin()) {
            forbidden(channel, "User is not authorized to log audit message");
            return;
        }
        super.handleApiRequest(channel, request, client);
    }

    @Override
    protected void handleDelete(RestChannel channel, RestRequest request, Client client, JsonNode content) throws IOException {
        notImplemented(channel, Method.DELETE);
    }

    @Override
    protected void handlePut(RestChannel channel, RestRequest request, Client client, JsonNode content) throws IOException {
        notImplemented(channel, Method.PUT);
    }

    @Override
    protected void handlePost(RestChannel channel, RestRequest request, Client client, JsonNode content) throws IOException {
        try (ThreadContext.StoredContext storedContext = threadPool.getThreadContext().stashContext()) {
            AuditLogApiRequestContent auditLogApiRequestContent = DefaultObjectMapper.readTree(content, AuditLogApiRequestContent.class);

            TransportAddress remoteAddress = null;
            if (auditLogApiRequestContent.remoteAddress != null) {
                String[] split = auditLogApiRequestContent.remoteAddress.split(":");
                remoteAddress = new TransportAddress(new InetSocketAddress(split[0], Integer.parseInt(split[1])));
            }
            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, remoteAddress);

            AuditLogHttpRequest httpRequest = new AuditLogHttpRequest(auditLogApiRequestContent.headers);
            AuditLogHttpChannel httpChannel = new AuditLogHttpChannel();
            request = RestRequest.request(request.getXContentRegistry(), httpRequest, httpChannel);

            switch (auditLogApiRequestContent.auditCategory) {
                case BAD_HEADERS:
                    if (auditLogApiRequestContent.headers == null) {
                        badRequestResponse(channel, "headers is required");
                        return;
                    }
                    auditLog.logBadHeaders(request);
                    break;
                case FAILED_LOGIN:
                    if (auditLogApiRequestContent.effectiveUser == null) {
                        badRequestResponse(channel, "user is required");
                        return;
                    }
                    auditLog.logFailedLogin(auditLogApiRequestContent.effectiveUser, false, null, request);
                    break;
                case MISSING_PRIVILEGES:
                    if (auditLogApiRequestContent.effectiveUser == null) {
                        badRequestResponse(channel, "user is required");
                        return;
                    }
                    auditLog.logMissingPrivileges(auditLogApiRequestContent.privilege, auditLogApiRequestContent.effectiveUser, request);
                    break;
                case SSL_EXCEPTION:
                    User user = null;
                    if (auditLogApiRequestContent.effectiveUser != null) {
                        user = new User(auditLogApiRequestContent.effectiveUser);
                    }
                    threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
                    auditLog.logSSLException(request, null);
                    break;
                case AUTHENTICATED:
                    if (auditLogApiRequestContent.effectiveUser == null) {
                        badRequestResponse(channel, "user is required");
                        return;
                    }
                    auditLog.logSucceededLogin(auditLogApiRequestContent.effectiveUser, false, null, request);
                    break;
                default:
                    badRequestResponse(channel, "Invalid audit category " + auditLogApiRequestContent.auditCategory);
                    return;
            }
            successResponse(channel, "Audit log request accepted");
        } catch (Exception e) {
            log.error("Invalid audit log request", e);
            badRequestResponse(channel, "Invalid audit log request");
        }
    }

    @Override
    protected void handleGet(RestChannel channel, RestRequest request, Client client, JsonNode content) throws IOException {
        notImplemented(channel, Method.GET);
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new AuditLogValidator(request, ref, settings, params);
    }

    @Override
    protected String getResourceName() {
        return null;
    }

    @Override
    protected CType getConfigName() {
        return null;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.AUDITLOG;
    }
}
