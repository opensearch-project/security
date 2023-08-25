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

package org.opensearch.security.dlic.rest.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

public class AuditApiActionValidationTest extends AbstractApiActionValidationTest {

    @Test
    public void disabledAuditApi() {
        final var auditApiAction = new AuditApiAction(clusterService, threadPool, securityApiDependencies);
        when(configurationRepository.isAuditHotReloadingEnabled()).thenReturn(false);

        for (final var m : RequestHandler.RequestHandlersBuilder.SUPPORTED_METHODS) {
            final var result = auditApiAction.withEnabledAuditApi(createRestRequest(m, Map.of()));
            assertFalse(result.isValid());
            assertEquals(RestStatus.NOT_IMPLEMENTED, result.status());
        }
    }

    @Test
    public void enabledAuditApi() {
        final var auditApiAction = new AuditApiAction(clusterService, threadPool, securityApiDependencies);
        when(configurationRepository.isAuditHotReloadingEnabled()).thenReturn(true);
        for (final var m : RequestHandler.RequestHandlersBuilder.SUPPORTED_METHODS) {
            final var result = auditApiAction.withEnabledAuditApi(createRestRequest(m, Map.of()));
            assertTrue(result.isValid());
        }
    }

    @Test
    public void configEntityNameOnly() {
        final var auditApiAction = new AuditApiAction(clusterService, threadPool, securityApiDependencies);
        var result = auditApiAction.withConfigEntityNameOnly(createRestRequest(RestRequest.Method.GET, Map.of("name", "aaaaa")));
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());

        result = auditApiAction.withConfigEntityNameOnly(createRestRequest(RestRequest.Method.GET, Map.of("name", "config")));
        assertTrue(result.isValid());
    }

    @Test
    public void onChangeVerifyReadonlyFields() throws Exception {
        final var auditApiActionEndpointValidator = new AuditApiAction(
            clusterService,
            threadPool,
            securityApiDependencies,
            List.of("/audit/enable_rest", "/audit/disabled_rest_categories", "/audit/ignore_requests", "/compliance/read_watched_fields")
        ).createEndpointValidator();

        final var auditFullConfig = objectMapper.createObjectNode();
        auditFullConfig.set("_meta", objectMapper.createObjectNode().put("type", "audit").put("config_version", 2));
        final var auditConfig = objectMapper.createObjectNode();
        auditConfig.put("enable_rest", false).set("disabled_rest_categories", objectMapper.createArrayNode());
        auditConfig.put("enable_transport", false).set("disabled_transport_categories", objectMapper.createArrayNode());
        auditConfig.set("ignore_users", objectMapper.createArrayNode().add("kibanaserver"));
        auditConfig.set("ignore_requests", objectMapper.createArrayNode());
        auditConfig.put("resolve_bulk_requests", false)
            .put("log_request_body", false)
            .put("resolve_indices", false)
            .put("exclude_sensitive_headers", false);

        auditFullConfig.set("config", objectMapper.createObjectNode().put("enabled", true).set("audit", auditConfig));
        final var dynamicConfiguration = SecurityDynamicConfiguration.fromJson(
            objectMapper.writeValueAsString(auditFullConfig),
            CType.AUDIT,
            2,
            1,
            1
        );
        final var result = auditApiActionEndpointValidator.onConfigChange(
            SecurityConfiguration.of(objectMapper.valueToTree(AuditConfig.from(Settings.EMPTY)), "config", dynamicConfiguration)
        );
        assertFalse(result.isValid());
        assertEquals(RestStatus.CONFLICT, result.status());
    }
}
