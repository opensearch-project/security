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

package org.opensearch.security.auditlog;

import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AbstractAuditLog;
import org.opensearch.security.auditlog.impl.AuditLogImpl;
import org.opensearch.security.test.helper.rest.RestHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ThreadPool;

import java.nio.file.Path;

import static org.junit.Assert.assertEquals;

public class AuditTestUtils {
    public static void updateAuditConfig(final RestHelper rh, final Settings settings) throws Exception {
        updateAuditConfig(rh, AuditTestUtils.createAuditPayload(settings));
    }

    public static void updateAuditConfig(final RestHelper rh, final String payload) throws Exception {
        final boolean sendAdminCertificate = rh.sendAdminCertificate;
        final String keystore = rh.keystore;
        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";
        RestHelper.HttpResponse response = rh.executePutRequest("_opendistro/_security/api/audit/config", payload);
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        rh.sendAdminCertificate = sendAdminCertificate;
        rh.keystore = keystore;
    }

    public static String createAuditPayload(final Settings settings) throws JsonProcessingException {
        final ObjectMapper objectMapper = new ObjectMapper();
        final AuditConfig audit = AuditConfig.from(settings);
        return objectMapper.writeValueAsString(audit);
    }

    public static String createAuditPayload(final AuditConfig audit) throws JsonProcessingException {
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(audit);
    }

    public static AbstractAuditLog createAuditLog(
        final Settings settings,
        final Path configPath,
        final Client clientProvider,
        final ThreadPool threadPool,
        final IndexNameExpressionResolver resolver,
        final ClusterService clusterService) {
        AuditLogImpl auditLog = new AuditLogImpl(settings, configPath, clientProvider, threadPool, resolver, clusterService);
        AuditConfig auditConfig = AuditConfig.from(settings);
        auditLog.setConfig(auditConfig);
        return auditLog;
    }
}
