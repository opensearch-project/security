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
import java.util.Objects;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.get.GetAliasesRequest;
import org.opensearch.action.admin.indices.alias.get.GetAliasesResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.awaitility.Awaitility.await;

/**
 * Integration tests for {@link InternalOpenSearchSink} with write alias configuration.
 *
 * <p>These tests validate the audit sink's ability to write to a pre-configured write alias
 * instead of creating date-based indices. This enables Index Lifecycle Management (ILM)
 * patterns such as rollover and retention policies.</p>
 *
 * <h3>Key Difference from Default Tests:</h3>
 * <p>While {@link InternalOpenSearchSinkIntegrationTest} tests the code path where
 * {@code metadata.hasIndex(indexName)} returns true (regular index creation), this class
 * tests the path where {@code metadata.hasAlias(indexName)} returns true (alias detection).</p>
 *
 * <h3>Configuration:</h3>
 * <p>Uses {@code plugins.security.audit.config.index} node setting to override the default
 * date-based pattern with a custom alias name: {@code security-audit-write-alias}</p>
 *
 * <h3>ILM Use Case Example:</h3>
 * <pre>
 * Initial Setup:
 *   Alias: "audit-write" → Index: "audit-000001" (is_write_index: true)
 *
 * Application writes to "audit-write" transparently
 *
 * ILM Policy Triggers Rollover:
 *   Alias: "audit-write" → Index: "audit-000002" (is_write_index: true)
 *   Old index "audit-000001" can be archived/deleted independently
 *
 * No configuration changes needed in audit sink!
 * </pre>
 *
 * <h3>Tested Code Path:</h3>
 * <pre>{@code
 * public boolean createIndexIfAbsent(String indexName) {
 *     if (metadata.hasAlias(indexName)) {
 *         log.debug("Audit log target '{}' is an alias...", indexName);
 *         return true; // THIS branch
 *     }
 *     // ... regular index creation
 * }
 * }</pre>
 *
 * @see InternalOpenSearchSinkIntegrationTest
 */
public class InternalOpenSearchSinkIntegrationTestAuditAlias {

    private static final String AUDIT_ALIAS = "security-audit-write-alias";
    private static final String BACKING_INDEX = "security-audit-backend-000001";

    /**
     * Cluster configuration with custom audit index override.
     *
     * <p>The {@code nodeSettings} override tells the audit sink to write to
     * {@code AUDIT_ALIAS} instead of the default {@code 'security-auditlog-'YYYY.MM.dd}.</p>
     */
    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(true)
        .nodeSettings(Map.of("plugins.security.audit.config.index", AUDIT_ALIAS))
        .internalAudit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(false)))
        .build();

    /**
     * Pre-creates the write alias and backing index before tests execute.
     *
     * <p>This setup simulates a production environment where ILM policies have already
     * established the alias structure. The audit sink should detect and use this alias
     * without attempting to create a regular index with the same name.</p>
     */
    @BeforeClass
    public static void setupAuditAlias() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.admin().indices().create(new CreateIndexRequest(BACKING_INDEX)).actionGet();

            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        IndicesAliasesRequest.AliasActions.add().index(BACKING_INDEX).alias(AUDIT_ALIAS).writeIndex(true)
                    )
                )
                .actionGet();
        }
    }

    // ----------------------------------------------------
    // Helpers
    // ----------------------------------------------------

    /**
     * Counts total audit documents by querying the alias.
     * Returns count across all backing indices resolved by the alias.
     */
    private long countAuditDocs(Client client) {
        SearchResponse response = client.search(
            new SearchRequest(AUDIT_ALIAS).source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(0))
        ).actionGet();

        return Objects.requireNonNull(response.getHits().getTotalHits()).value();
    }

    /**
     * Generates a single REST audit event via GET request.
     */
    private void generateAuditEvent(String path) {
        try (TestRestClient restClient = cluster.getRestClient(cluster.getAdminCertificate())) {
            restClient.get(path);
        }
    }

    // ----------------------------------------------------
    // Tests
    // ----------------------------------------------------

    /**
     * Verifies that the audit sink correctly identifies a write alias and uses it
     * as the audit target instead of attempting to create a regular index.
     *
     * <p><b>Test Flow:</b></p>
     * <ol>
     *   <li>Generate audit event to trigger sink initialization</li>
     *   <li>Verify alias exists in cluster metadata</li>
     *   <li>Verify alias resolves to a concrete backing index</li>
     *   <li>Confirm backing index name differs from alias name</li>
     *   <li>Verify backing index physically exists</li>
     * </ol>
     *
     * <p><b>Why This Matters:</b> If the sink incorrectly treats the alias as a
     * regular index name, it would attempt {@code CreateIndexRequest(AUDIT_ALIAS)},
     * which would fail because an alias with that name already exists.</p>
     *
     * <p><b>Covered Code:</b></p>
     * <pre>{@code
     * if (metadata.hasAlias(indexName)) {
     *     return true; // Detected alias - no index creation
     * }
     * }</pre>
     */
    @Test
    public void testRecognizesAuditTargetAsWriteAlias() {
        try (Client client = cluster.getInternalNodeClient()) {
            generateAuditEvent("_cluster/health");

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).until(() -> countAuditDocs(client) > 0);

            GetAliasesResponse aliasesResponse = client.admin().indices().getAliases(new GetAliasesRequest(AUDIT_ALIAS)).actionGet();
            assertThat("Write alias must exist", aliasesResponse.getAliases().isEmpty(), is(false));

            String concreteIndex = aliasesResponse.getAliases().keySet().iterator().next();
            assertThat("Alias must resolve to a concrete index", concreteIndex, not(equalTo(AUDIT_ALIAS)));

            boolean backendIndexExists = client.admin().indices().exists(new IndicesExistsRequest(concreteIndex)).actionGet().isExists();
            assertThat("Concrete backing index must exist", backendIndexExists, is(true));
        }
    }

    /**
     * Verifies that the audit sink reuses an existing write alias without attempting
     * to recreate it, and successfully writes events to the backing index.
     *
     * <p><b>Test Strategy:</b> Measures document count delta (before/after) to confirm
     * new events are written to the alias structure established in {@code @BeforeClass}.</p>
     *
     * <p><b>Expected Behavior:</b></p>
     * <ul>
     *   <li>Sink detects existing alias via {@code metadata.hasAlias()}</li>
     *   <li>Returns {@code true} immediately (no index creation attempt)</li>
     *   <li>Writes event to alias, which OpenSearch routes to the write index</li>
     * </ul>
     *
     * <p><b>Covered Code:</b></p>
     * <pre>{@code
     * if (metadata.hasAlias(indexName)) {
     *     return true; // Reuse existing alias
     * }
     * }</pre>
     */
    @Test
    public void testReusesExistingAliasWithoutRecreation() {
        try (Client client = cluster.getInternalNodeClient()) {
            long before = countAuditDocs(client);
            generateAuditEvent("_cluster/stats");

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).until(() -> countAuditDocs(client) > before);

            long after = countAuditDocs(client);
            assertThat("New audit event must be persisted via existing alias", after, greaterThan(before));
        }
    }

    /**
     * Validates that audit documents written via alias contain the same mandatory
     * fields as those written to regular indices, ensuring alias usage doesn't
     * affect document structure.
     *
     * <p><b>Validated Core Fields (required for all audit events):</b></p>
     * <ul>
     *   <li>{@code audit_category} - Event classification</li>
     *   <li>{@code audit_request_origin} - Origin layer (REST/TRANSPORT)</li>
     *   <li>{@code @timestamp} - Event timestamp</li>
     * </ul>
     *
     * <p><b>Validated REST-Specific Fields:</b></p>
     * <ul>
     *   <li>{@code audit_rest_request_method} - HTTP method</li>
     *   <li>{@code audit_rest_request_path} - Request path</li>
     *   <li>{@code audit_request_layer} - Must be "REST" for REST events</li>
     * </ul>
     *
     * <p><b>Validated Exclusions:</b></p>
     * <ul>
     *   <li>{@code audit_transport_request_type} - Must NOT exist for REST events</li>
     * </ul>
     *
     * <p><b>Test Strategy:</b> Generates a fresh event and validates the most recent
     * document to avoid contamination from previous tests. Uses delta to ensure this
     * test created a new event.</p>
     */
    @Test
    public void testAuditDocumentsViaAliasContainMandatoryFields() {
        try (Client client = cluster.getInternalNodeClient()) {
            long before = countAuditDocs(client);
            generateAuditEvent("_cluster/health");

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).until(() -> countAuditDocs(client) > before);

            SearchResponse response = client.search(
                new SearchRequest(AUDIT_ALIAS).source(
                    new SearchSourceBuilder().query(QueryBuilders.matchAllQuery())
                        .size(1)
                        .sort("@timestamp", org.opensearch.search.sort.SortOrder.DESC)
                )
            ).actionGet();

            Map<String, Object> doc = response.getHits().getAt(0).getSourceAsMap();

            assertThat(doc, hasKey("audit_category"));
            assertThat(doc, hasKey("audit_request_origin"));
            assertThat(doc, hasKey("@timestamp"));
            assertThat(doc, hasKey("audit_rest_request_method"));
            assertThat(doc, hasKey("audit_rest_request_path"));
            assertThat(doc, hasKey("audit_request_layer"));
            assertThat(doc.get("audit_request_layer"), is("REST"));
            assertThat(doc.get("audit_request_origin"), is("REST"));
            assertThat(doc, not(hasKey("audit_transport_request_type")));
        }
    }

    /**
     * Verifies that multiple audit events accumulate in the alias over time,
     * demonstrating continuous write capability.
     *
     * <p><b>Real-World Scenario:</b> In production with ILM, this alias might
     * roll over to new backing indices (e.g., audit-000002, audit-000003) while
     * maintaining a consistent write target name. The audit sink doesn't need
     * to know about these rollovers—it continues writing to the same alias.</p>
     *
     * <p><b>Test Strategy:</b> Uses delta-based counting to ensure test isolation
     * from previous test executions.</p>
     */
    @Test
    public void testMultipleEventsAccumulateInAlias() {
        try (Client client = cluster.getInternalNodeClient()) {
            long before = countAuditDocs(client);

            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");
            generateAuditEvent("_nodes/info");

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).until(() -> countAuditDocs(client) - before >= 3);

            long after = countAuditDocs(client);
            assertThat("Three REST requests must generate at least 3 new audit events", after - before, greaterThanOrEqualTo(3L));
        }
    }
}
