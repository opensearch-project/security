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

package org.opensearch.security.auditlog;

import java.util.Arrays;
import java.util.Collection;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.hc.core5.http.Header;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.routing.AuditMessageRouter;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.opensearch.security.auditlog.config.AuditConfig.DEPRECATED_KEYS;

public abstract class AbstractAuditlogiUnitTest extends SingleClusterTest {

    protected RestHelper rh = null;
    protected boolean init = true;

    @Override
    protected String getResourceFolder() {
        return "auditlog";
    }

    protected final void setup(Settings settings) throws Exception {
        final Settings.Builder auditConfigSettings = Settings.builder();
        final Settings.Builder defaultNodeSettings = Settings.builder();
        // Separate the cluster defaults from audit settings that will be applied after the cluster is up
        settings.keySet().forEach(key -> {
            final boolean moveToAuditConfig = Arrays.stream(AuditConfig.Filter.FilterEntries.values())
                .anyMatch(
                    entry -> entry.getKeyWithNamespace().equalsIgnoreCase(key) || entry.getLegacyKeyWithNamespace().equalsIgnoreCase(key)
                )
                || DEPRECATED_KEYS.stream().anyMatch(key::equalsIgnoreCase);
            if (moveToAuditConfig) {
                auditConfigSettings.put(key, settings.get(key));
            } else {
                defaultNodeSettings.put(key, settings.get(key));
            }
        });

        final Settings nodeSettings = defaultNodeSettings(defaultNodeSettings.build());
        setup(Settings.EMPTY, new DynamicSecurityConfig(), nodeSettings, init);
        rh = restHelper();
        updateAuditConfig(auditConfigSettings.build());
    }

    protected Settings defaultNodeSettings(Settings additionalSettings) {
        Settings.Builder builder = Settings.builder();

        builder.put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore.jks"));

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
        for (AuditMessage msg : msgs) {
            valid = validateMsg(msg) && valid;
        }
        return valid;
    }

    protected boolean validateMsg(final AuditMessage msg) {
        return validateJson(msg.toJson()) && validateJson(msg.toPrettyString());
    }

    protected boolean validateJson(final String json) {

        if (json == null || json.isEmpty()) {
            return false;
        }

        try {
            JsonNode node = DefaultObjectMapper.objectMapper.readTree(json);

            if (node.get("audit_request_body") != null) {
                System.out.println("    Check audit_request_body for validity: " + node.get("audit_request_body").asText());
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
