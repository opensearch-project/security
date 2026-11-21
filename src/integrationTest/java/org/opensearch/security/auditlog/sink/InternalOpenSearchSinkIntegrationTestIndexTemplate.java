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
package org.opensearch.security.auditlog.sink;

import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.admin.cluster.state.ClusterStateRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.client.Client;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.awaitility.Awaitility.await;

/**
 * Integration tests for the audit log index template created by {@link InternalOpenSearchSink} when
 * {@code plugins.security.audit.config.index_template.enabled} is {@code true}.
 *
 * <p>Shared tests ({@code testPersistsAuditEventsToTarget} and {@code testAuditDocumentContainsMandatoryFields}) are
 * inherited from {@link AbstractInternalOpenSearchSinkIntegrationTest} and verify that audit events are still
 * accepted by the explicitly mapped indices.</p>
 *
 * @see InternalOpenSearchSinkIndexTemplateTest for unit tests of the index template
 */
public class InternalOpenSearchSinkIntegrationTestIndexTemplate extends AbstractInternalOpenSearchSinkIntegrationTest {

    private static final String AUDIT_INDEX_PREFIX = "security-auditlog-";

    @ClassRule
    public static final LocalCluster CLUSTER = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .nodeSettings(Map.of("plugins.security.audit.config.index_template.enabled", true))
        .internalAudit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(false)))
        .build();

    @Override
    LocalCluster cluster() {
        return CLUSTER;
    }

    @Override
    String auditTarget() {
        return AUDIT_INDEX_PREFIX + "*";
    }

    private void awaitAuditDocument(Client client) {
        generateAuditEvent("_cluster/health");
        await().atMost(10, SECONDS).pollInterval(200, MILLISECONDS).untilAsserted(() -> {
            refreshAuditTarget(client);
            assertThat("At least one audit event must be persisted", countAuditDocs(client), greaterThan(0L));
        });
    }

    /** The sink must create the index template with the derived index pattern before it creates the audit index. */
    @Test
    public void testCreatesIndexTemplate() {
        try (Client client = CLUSTER.getInternalNodeClient()) {
            awaitAuditDocument(client);

            ComposableIndexTemplate template = client.admin()
                .cluster()
                .state(new ClusterStateRequest().metadata(true))
                .actionGet()
                .getState()
                .metadata()
                .templatesV2()
                .get("security-auditlog");

            assertThat("Index template security-auditlog must exist", template, notNullValue());
            assertThat(template.indexPatterns(), contains(AUDIT_INDEX_PREFIX + "*"));
            assertThat(template.version(), is(AuditLogIndexTemplate.VERSION));
        }
    }

    /** The audit index must use the explicit mappings of the index template instead of dynamically detected ones. */
    @Test
    @SuppressWarnings("unchecked")
    public void testAuditIndexUsesTemplateMappings() {
        try (Client client = CLUSTER.getInternalNodeClient()) {
            awaitAuditDocument(client);

            Map<String, MappingMetadata> mappings = client.admin()
                .indices()
                .getMappings(new GetMappingsRequest().indices(auditTarget()))
                .actionGet()
                .mappings();
            assertThat("At least one audit index must exist", mappings.size(), greaterThan(0));

            for (Map.Entry<String, MappingMetadata> entry : mappings.entrySet()) {
                Map<String, Object> properties = (Map<String, Object>) entry.getValue().sourceAsMap().get("properties");
                assertThat(entry.getKey(), ((Map<String, Object>) properties.get("audit_category")).get("type"), is("keyword"));
                assertThat(entry.getKey(), ((Map<String, Object>) properties.get("audit_node_host_address")).get("type"), is("ip"));
                assertThat(entry.getKey(), ((Map<String, Object>) properties.get("@timestamp")).get("type"), is("date"));
            }
        }
    }
}
