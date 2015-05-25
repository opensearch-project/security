/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.audit;

import java.net.UnknownHostException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.collect.Iterables;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

public class ESStoreAuditListener implements AuditListener {

    private final Client client;
    private final Settings settings;
    private final String securityConfigurationIndex;
    protected final ESLogger log = Loggers.getLogger(this.getClass());

    @Inject
    public ESStoreAuditListener(final Client client, final Settings settings) {
        super();
        this.client = client;
        this.settings = settings;
        securityConfigurationIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME,
                ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX);
    }

    @Override
    public void onFailedLogin(final String username, final RestRequest request) {

        final AuditMessage msg = new AuditMessage(username, "failed_login", request);
        index(msg);

    }

    @Override
    public void onMissingPrivileges(final String username, final RestRequest request) {

        final AuditMessage msg = new AuditMessage(username, "missing_privileges", request);
        index(msg);

    }

    @Override
    public void onFailedLogin(final String username, final TransportRequest request) {

        final AuditMessage msg = new AuditMessage(username, "failed_login", request);
        index(msg);

    }

    @Override
    public void onMissingPrivileges(final String username, final TransportRequest request) {

        final AuditMessage msg = new AuditMessage(username, "missing_privileges", request);
        index(msg);

    }

    protected void index(final AuditMessage msg) {
        client.prepareIndex(securityConfigurationIndex, "audit").setSource(msg.auditInfo).execute(new ActionListener<IndexResponse>() {

            @Override
            public void onResponse(final IndexResponse response) {
                log.trace("write audit message {}", msg);

            }

            @Override
            public void onFailure(final Throwable e) {
                log.error("Unable to write audit log due to {}", e, e.toString());
            }
        });
    }

    private class AuditMessage {
        final Map<String, Object> auditInfo = new HashMap<String, Object>();

        private AuditMessage(final String username, final String message, final TransportRequest request) {
            auditInfo.put("audit_user", username);
            auditInfo.put("audit_message", message);
            auditInfo.put("audit_date", new Date().toString());
            auditInfo.put("audit_details_context", String.valueOf(request.getContext()));
            auditInfo.put("audit_details_headers", String.valueOf(request.getHeaders()));
            auditInfo.put("audit_details_class", request.getClass().toString());
            auditInfo.put("audit_ip", String.valueOf(request.remoteAddress()));

        }

        private AuditMessage(final String username, final String message, final RestRequest request) {
            auditInfo.put("audit_user", username);
            auditInfo.put("audit_message", message);
            auditInfo.put("audit_date", new Date().toString());
            auditInfo.put("audit_details_context", String.valueOf(request.getContext()));
            auditInfo.put("audit_details_headers", Iterables.toString(request.headers()));
            auditInfo.put("audit_details_rest", request.method() + " " + request.path() + " " + request.params());
            auditInfo.put("audit_details_class", request.getClass().toString());
            try {
                auditInfo.put("audit_ip", SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings).toString());
            } catch (final UnknownHostException e) {
                //no-op
            }
        }

        @Override
        public String toString() {
            return "AuditMessage [auditInfo=" + auditInfo + "]";
        }

    }

}