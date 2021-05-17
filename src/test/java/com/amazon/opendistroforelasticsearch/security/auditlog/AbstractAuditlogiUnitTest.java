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

package com.amazon.opendistroforelasticsearch.security.auditlog;

import java.util.Collection;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import org.apache.http.Header;
import org.opensearch.common.settings.Settings;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.AuditMessageRouter;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.fasterxml.jackson.databind.JsonNode;

public abstract class AbstractAuditlogiUnitTest extends SingleClusterTest {

    protected RestHelper rh = null;
    protected boolean init = true;

    @Override
    protected String getResourceFolder() {
        return "auditlog";
    }

    protected final void setup(Settings additionalSettings) throws Exception {
        final Settings.Builder auditSettingsBuilder = Settings.builder();
        final Settings.Builder additionalSettingsBuilder = Settings.builder().put(additionalSettings);
        AuditConfig.DEPRECATED_KEYS.forEach(key -> {
            if (additionalSettingsBuilder.get(key) != null) {
                auditSettingsBuilder.put(key, additionalSettings.get(key));
                additionalSettingsBuilder.remove(key);
            }
        });

        final Settings nodeSettings = defaultNodeSettings(additionalSettingsBuilder.build());
        setup(Settings.EMPTY, new DynamicSecurityConfig(), nodeSettings, init);
        rh = restHelper();
        updateAuditConfig(auditSettingsBuilder.build());
    }

    protected Settings defaultNodeSettings(Settings additionalSettings) {
        Settings.Builder builder = Settings.builder();

        builder.put("opendistro_security.ssl.http.enabled", true)
                .put("opendistro_security.ssl.http.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore.jks"));

        return builder.put(additionalSettings).build();
    }

    protected void setupStarfleetIndex() throws Exception {
        final boolean sendAdminCertificate = rh.sendAdminCertificate;
        final String keystore = rh.keystore;
        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";
        rh.executePutRequest("sf", null, new Header[0]);
        rh.executePutRequest("sf/public/0?refresh", "{\"number\" : \"NCC-1701-D\"}", new Header[0]);
        rh.executePutRequest("sf/public/0?refresh", "{\"some\" : \"value\"}", new Header[0]);
        rh.executePutRequest("sf/public/0?refresh", "{\"some\" : \"value\"}", new Header[0]);
        rh.sendAdminCertificate = sendAdminCertificate;
        rh.keystore = keystore;
    }

    protected boolean validateMsgs(final Collection<AuditMessage> msgs) {
        boolean valid = true;
        for(AuditMessage msg: msgs) {
            valid = validateMsg(msg) && valid;
        }
        return valid;
    }

    protected boolean validateMsg(final AuditMessage msg) {
        return validateJson(msg.toJson()) && validateJson(msg.toPrettyString());
    }

    protected boolean validateJson(final String json) {

        if(json == null || json.isEmpty()) {
            return false;
        }

        try {
            JsonNode node = DefaultObjectMapper.objectMapper.readTree(json);

            if(node.get("audit_request_body") != null) {
                System.out.println("    Check audit_request_body for validity: "+node.get("audit_request_body").asText());
                DefaultObjectMapper.objectMapper.readTree(node.get("audit_request_body").asText());
            }

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    protected AuditMessageRouter createMessageRouterComplianceEnabled(Settings settings) {
        AuditMessageRouter router = new AuditMessageRouter(settings, null, null, null);
        router.enableRoutes(settings);
        return router;
    }

    protected void updateAuditConfig(final Settings settings) throws Exception {
        updateAuditConfig(AuditTestUtils.createAuditPayload(settings));
    }

    protected void updateAuditConfig(final String payload) throws Exception {
        final boolean sendAdminCertificate = rh.sendAdminCertificate;
        final String keystore = rh.keystore;
        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";
        RestHelper.HttpResponse response = rh.executePutRequest("_opendistro/_security/api/audit/config", payload, new Header[0]);
        System.out.println(response);
        rh.sendAdminCertificate = sendAdminCertificate;
        rh.keystore = keystore;
    }
}
