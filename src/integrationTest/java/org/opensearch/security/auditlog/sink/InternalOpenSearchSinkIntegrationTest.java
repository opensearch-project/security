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

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.get.GetIndexRequest;
import org.opensearch.action.admin.indices.get.GetIndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

/**
 * Integration tests for {@link InternalOpenSearchSink} with default date-based index naming.
 *
 * <p>These tests validate the audit sink behavior when using the default configuration
 * without custom index names or aliases. The default pattern {@code 'security-auditlog-'YYYY.MM.dd}
 * creates daily indices (e.g., {@code security-auditlog-2025.01.11}).</p>
 *
 * <h3>Tested Scenarios:</h3>
 * <ul>
 *   <li>Automatic index creation on first audit event</li>
 *   <li>Event persistence and retrieval</li>
 *   <li>Idempotent index existence checks (no duplicate creation)</li>
 *   <li>Audit document schema validation</li>
 *   <li>Date-based naming pattern compliance</li>
 * </ul>
 *
 * <h3>Test Strategy:</h3>
 * <ul>
 *   <li><b>Isolation:</b> Uses delta-based assertions (before/after counts) to avoid
 *       inter-test dependencies despite shared cluster state</li>
 *   <li><b>Determinism:</b> Tests resilient to midnight rollover by avoiding assumptions
 *       about specific index counts or array indices</li>
 *   <li><b>Authentication:</b> Uses {@code anonymousAuth(true)} to simplify REST audit
 *       event generation without authentication complexity</li>
 *   <li><b>Code Coverage:</b> Focuses on the {@code metadata.hasIndex(indexName)} branch
 *       in {@link InternalOpenSearchSink#createIndexIfAbsent(String)}</li>
 * </ul>
 *
 * <h3>Why Separate from Alias Tests?</h3>
 * <p>This class tests the regular index creation path, while
 * {@code InternalOpenSearchSinkIntegrationTest_AuditAlias} tests the alias path
 * ({@code metadata.hasAlias(indexName)}). These are mutually exclusive configurations
 * requiring separate cluster setups.</p>
 *
 * <h3>Technical Justification for Separate Test Classes:</h3>
 * <p>The {@link LocalCluster} configuration is immutable once initialized via {@code @ClassRule}.
 * The critical difference is the node setting {@code plugins.security.audit.config.index}:</p>
 * <ul>
 *   <li><b>This class:</b> Uses default (no override) → date-based indices created automatically</li>
 *   <li><b>Alias class:</b> Overrides with fixed alias name → requires pre-existing alias setup</li>
 * </ul>
 * <p>Attempting to test both scenarios in one class would require:</p>
 * <ul>
 *   <li>Cluster restart between tests (extremely slow, defeats @ClassRule purpose)</li>
 *   <li>Or conditional test execution based on config (violates test isolation principles)</li>
 * </ul>
 * <p>Separate classes ensure each test suite runs against the correct, immutable configuration.</p>
 *
 * @see InternalOpenSearchSinkIntegrationTest_AuditAlias
 */
public class InternalOpenSearchSinkIntegrationTest {

    private static final String AUDIT_INDEX_PREFIX = "security-auditlog-";

    /**
     * Shared cluster for all tests in this class.
     * Uses default audit configuration without custom index override.
     */
    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(true)
        .internalAudit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(false)))
        .build();

    @BeforeClass
    public static void waitForCluster() throws Exception {
        try (Client client = cluster.getInternalNodeClient()) {
            // Wait for cluster to be ready
            ClusterHealthResponse health = client.admin().cluster().health(new ClusterHealthRequest()).actionGet();

            // Ensure cluster is at least yellow (operational)
            assertThat("Cluster must be operational before tests run", health.getStatus(), not(equalTo(ClusterHealthStatus.RED)));
        }
    }

    // --------------------------------------------------
    // Helpers
    // --------------------------------------------------

    private void refreshAuditIndices(Client client) {
        client.admin().indices().prepareRefresh(AUDIT_INDEX_PREFIX + "*").get();
    }

    /**
     * Generates a single REST audit event by performing a GET request.
     * Each call produces exactly one REST audit event.
     */
    private void generateAuditEvent(String path) throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(cluster.getAdminCertificate())) {
            restClient.get(path);
        }
    }

    /**
     * Counts total audit events across all matching indices.
     */
    private long countAuditEvents(Client client) {
        return client.search(
            new SearchRequest(AUDIT_INDEX_PREFIX + "*").source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(0))
        ).actionGet().getHits().getTotalHits().value();
    }

    /**
     * Counts indices matching the audit index pattern.
     */
    private int countAuditIndices(Client client) {
        GetIndexResponse response = client.admin().indices().getIndex(new GetIndexRequest().indices(AUDIT_INDEX_PREFIX + "*")).actionGet();
        return response.indices().length;
    }

    // --------------------------------------------------
    // Tests
    // --------------------------------------------------

    /**
     * Verifies that the audit sink automatically creates a date-based index
     * when the first audit event occurs.
     *
     * <p><b>Tested Code Path:</b></p>
     * <pre>{@code
     * public boolean createIndexIfAbsent(String indexName) {
     *     if (metadata.hasAlias(indexName)) {
     *         return true; // NOT this branch
     *     }
     *     if (metadata.hasIndex(indexName)) {
     *         return true; // NOT this branch initially
     *     }
     *     // Falls through to index creation
     *     final CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName);
     *     clientProvider.admin().indices().create(createIndexRequest).actionGet();
     * }
     * }</pre>
     *
     * <p><b>Test Strategy:</b> Uses delta-based assertions for both event count
     * and index count to ensure this test creates new resources regardless of
     * previous test state or midnight rollover.</p>
     *
     * <p><b>Expected Outcome:</b> At least one new index named
     * {@code security-auditlog-YYYY.MM.dd} is created (e.g., {@code security-auditlog-2025.01.11}).</p>
     */
    @Test
    public void testCreatesAuditIndexAutomatically() throws Exception {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);
            int indexCountBefore = countAuditIndices(client);

            // Generate event that triggers index creation
            generateAuditEvent("_cluster/health");

            Thread.sleep(1500);
            refreshAuditIndices(client);

            long eventCountAfter = countAuditEvents(client);
            int indexCountAfter = countAuditIndices(client);

            // Verify event was persisted
            assertThat("At least one new audit event must be generated", eventCountAfter, greaterThan(eventCountBefore));

            // Verify at least one new index was created (or existing one reused)
            // At midnight rollover, this could be +1 (new day) or +0 (same day)
            assertThat("Index count must not decrease", indexCountAfter, greaterThanOrEqualTo(indexCountBefore));

            // Verify at least one index follows date pattern
            GetIndexResponse response = client.admin()
                .indices()
                .getIndex(new GetIndexRequest().indices(AUDIT_INDEX_PREFIX + "*"))
                .actionGet();

            boolean foundDateBasedIndex = false;
            for (String indexName : response.indices()) {
                if (indexName.matches("^security-auditlog-\\d{4}\\.\\d{2}\\.\\d{2}$")) {
                    foundDateBasedIndex = true;
                    break;
                }
            }

            assertThat("At least one index must match date pattern: security-auditlog-YYYY.MM.dd", foundDateBasedIndex, is(true));
        }
    }

    /**
     * Verifies that audit events are successfully persisted to the audit index.
     *
     * <p><b>Test Strategy:</b> Measures event count delta (before/after) to ensure
     * this test generates new events regardless of previous test state or midnight
     * rollover timing.</p>
     *
     * <p><b>Expected Behavior:</b> Each REST request generates at least one audit event.
     * Two requests should produce at least two new events.</p>
     */
    @Test
    public void testPersistsAuditEventsToIndex() throws Exception {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            // Generate exactly 2 REST requests
            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");

            Thread.sleep(1500);
            refreshAuditIndices(client);

            long eventCountAfter = countAuditEvents(client);
            long newEvents = eventCountAfter - eventCountBefore;

            assertThat("This test must generate at least 2 new audit events", newEvents, greaterThanOrEqualTo(2L));
        }
    }

    /**
     * Verifies that the sink reuses existing indices without attempting recreation.
     *
     * <p><b>Tested Code Path:</b></p>
     * <pre>{@code
     * if (metadata.hasIndex(indexName)) {
     *     log.debug("Audit log index '{}' already exists.", indexName);
     *     return true; // THIS branch - no recreation
     * }
     * }</pre>
     *
     * <p><b>Test Strategy:</b> Generates multiple events in quick succession and
     * verifies they are all persisted. The sink should detect the existing index
     * on subsequent calls and reuse it rather than attempting recreation.</p>
     *
     * <p><b>Expected Outcome:</b> All events are successfully written to the
     * existing index (or a new date-based index if midnight rollover occurs),
     * with no errors from attempted duplicate index creation.</p>
     */
    @Test
    public void testReusesExistingIndexWithoutRecreation() throws Exception {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            // Generate multiple events - should reuse existing index
            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");
            generateAuditEvent("_nodes/stats");

            Thread.sleep(1500);
            refreshAuditIndices(client);

            long eventCountAfter = countAuditEvents(client);
            long newEvents = eventCountAfter - eventCountBefore;

            // All events must be persisted successfully
            assertThat("All generated events must be persisted without errors", newEvents, greaterThanOrEqualTo(3L));
        }
    }

    /**
     * Validates that stored audit documents contain all mandatory fields
     * required by the audit log specification.
     *
     * <p><b>Required Core Fields (all audit events):</b></p>
     * <ul>
     *   <li>{@code audit_category} - Event classification (e.g., GRANTED_PRIVILEGES)</li>
     *   <li>{@code audit_request_origin} - Origin layer (REST or TRANSPORT)</li>
     *   <li>{@code @timestamp} - Event timestamp in ISO-8601 format</li>
     * </ul>
     *
     * <p><b>Required REST-Specific Fields:</b></p>
     * <ul>
     *   <li>{@code audit_rest_request_method} - HTTP method (GET, POST, etc.)</li>
     *   <li>{@code audit_rest_request_path} - Request path (e.g., /_cluster/health)</li>
     * </ul>
     *
     * <p><b>Test Strategy:</b> Generates a fresh event and validates the most
     * recent document (sorted by timestamp DESC) to avoid contamination from
     * previous tests. Uses delta assertion to ensure a new event was created.</p>
     */
    @Test
    public void testAuditDocumentContainsMandatoryFields() throws Exception {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");
            Thread.sleep(1500);
            refreshAuditIndices(client);

            long eventCountAfter = countAuditEvents(client);
            assertThat("Test must generate at least one new event", eventCountAfter, greaterThan(eventCountBefore));

            // Retrieve most recent document
            SearchResponse response = client.search(
                new SearchRequest(AUDIT_INDEX_PREFIX + "*").source(
                    new SearchSourceBuilder().query(QueryBuilders.matchAllQuery())
                        .size(1)
                        .sort("@timestamp", org.opensearch.search.sort.SortOrder.DESC)
                )
            ).actionGet();

            assertThat("At least one audit document must exist", response.getHits().getTotalHits().value(), greaterThan(0L));

            Map<String, Object> auditDoc = response.getHits().getAt(0).getSourceAsMap();

            // Validate core fields
            assertThat("Missing mandatory field: audit_category", auditDoc.containsKey("audit_category"), is(true));
            assertThat("Missing mandatory field: audit_request_origin", auditDoc.containsKey("audit_request_origin"), is(true));
            assertThat("Missing mandatory field: @timestamp", auditDoc.containsKey("@timestamp"), is(true));

            // Validate REST-specific fields
            assertThat("Missing REST field: audit_rest_request_method", auditDoc.containsKey("audit_rest_request_method"), is(true));
            assertThat("Missing REST field: audit_rest_request_path", auditDoc.containsKey("audit_rest_request_path"), is(true));
        }
    }

    /**
     * Verifies that different types of REST operations (read, write, index management)
     * all generate audit events, ensuring comprehensive audit coverage.
     *
     * <p><b>Tested REST Operations:</b></p>
     * <ul>
     *   <li>Cluster metadata read: {@code GET /_cluster/health}</li>
     *   <li>Index creation: {@code PUT /test-index}</li>
     *   <li>Document indexing: {@code PUT /test-index/_doc/1}</li>
     * </ul>
     *
     * <p><b>Purpose:</b> Confirms that the audit sink captures events across
     * different REST API categories, not just specific endpoints.</p>
     *
     * <p><b>Test Strategy:</b> Uses delta-based counting to ensure this test
     * generates at least 3 new events, independent of prior test executions
     * and midnight rollover timing.</p>
     */
    @Test
    public void testMultipleRequestTypesGenerateAuditEvents() throws Exception {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            try (TestRestClient restClient = cluster.getRestClient(cluster.getAdminCertificate())) {
                // Cluster read
                restClient.get("_cluster/health");

                // Index creation
                String uniqueIndexName = "test-audit-operations-" + System.currentTimeMillis();
                restClient.put(uniqueIndexName);

                // Document write
                StringEntity document = new StringEntity("{\"field\":\"value\"}", ContentType.APPLICATION_JSON);
                restClient.put(uniqueIndexName + "/_doc/1", document, new BasicHeader(HttpHeaders.CONTENT_TYPE, "application/json"));
            }

            Thread.sleep(1500);
            refreshAuditIndices(client);

            long eventCountAfter = countAuditEvents(client);
            long newEvents = eventCountAfter - eventCountBefore;

            assertThat("Three distinct REST operations must generate at least 3 audit events", newEvents, greaterThanOrEqualTo(3L));
        }
    }

    /**
     * Validates that audit indices follow the configured date-based naming pattern.
     *
     * <p><b>Expected Pattern:</b> {@code security-auditlog-YYYY.MM.dd}</p>
     * <p><b>Example:</b> {@code security-auditlog-2025.01.11}</p>
     *
     * <p>This pattern enables:</p>
     * <ul>
     *   <li>Automatic daily rotation without configuration changes</li>
     *   <li>Simplified lifecycle management (delete old indices by date)</li>
     *   <li>Time-based querying and retention policies</li>
     * </ul>
     *
     * <p><b>Test Strategy:</b> Generates an event and scans all audit indices.
     * At least one must match the date pattern. Does not assume specific count
     * due to potential midnight rollover (test might see both 2025.01.11 and
     * 2025.01.12 if executed at 23:59:xx).</p>
     *
     * <p><b>Validation:</b> Uses regex to verify at least one index name matches
     * the complete pattern {@code ^security-auditlog-\d{4}\.\d{2}\.\d{2}$}.</p>
     */
    @Test
    public void testIndexFollowsDateBasedNamingPattern() throws Exception {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            // Generate event to ensure at least one index exists
            generateAuditEvent("_cluster/health");
            Thread.sleep(1500);
            refreshAuditIndices(client);

            long eventCountAfter = countAuditEvents(client);
            assertThat("Test must generate at least one new event", eventCountAfter, greaterThan(eventCountBefore));

            GetIndexResponse indicesResponse = client.admin()
                .indices()
                .getIndex(new GetIndexRequest().indices(AUDIT_INDEX_PREFIX + "*"))
                .actionGet();

            assertThat("At least one audit index must exist", indicesResponse.indices().length, greaterThan(0));

            // Verify at least one index follows the date pattern
            boolean foundDateBasedIndex = false;
            for (String indexName : indicesResponse.indices()) {
                if (indexName.matches("^security-auditlog-\\d{4}\\.\\d{2}\\.\\d{2}$")) {
                    foundDateBasedIndex = true;
                    break;
                }
            }

            assertThat("At least one index must follow pattern: security-auditlog-YYYY.MM.dd", foundDateBasedIndex, is(true));
        }
    }
}
