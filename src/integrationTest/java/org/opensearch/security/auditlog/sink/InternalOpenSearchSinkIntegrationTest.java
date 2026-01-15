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

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.admin.indices.get.GetIndexRequest;
import org.opensearch.action.admin.indices.get.GetIndexResponse;
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
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.awaitility.Awaitility.await;

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
 * {@code InternalOpenSearchSinkIntegrationTestAuditAlias} tests the alias path
 * ({@code metadata.hasAlias(indexName)}). These are mutually exclusive configurations
 * requiring separate cluster setups.</p>
 *
 * @see InternalOpenSearchSinkIntegrationTestAuditAlias
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
    private void generateAuditEvent(String path) {
        try (TestRestClient restClient = cluster.getRestClient(cluster.getAdminCertificate())) {
            restClient.get(path);
        }
    }

    /**
     * Counts total audit events across all matching indices.
     */
    private long countAuditEvents(Client client) {
        return Objects.requireNonNull(
            client.search(
                new SearchRequest(AUDIT_INDEX_PREFIX + "*").source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(0))
            ).actionGet().getHits().getTotalHits()
        ).value();
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
     * <p><b>Test Strategy:</b> Generates an event and verifies that at least one
     * index matching the date pattern exists. Does not assume specific count due
     * to potential midnight rollover during test execution.</p>
     *
     * <p><b>Expected Outcome:</b> At least one index named {@code security-auditlog-YYYY.MM.dd}
     * exists after event generation (e.g., {@code security-auditlog-2025.01.11}).</p>
     */
    @Test
    public void testCreatesAuditIndexAutomatically() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditIndices(client); // refresh prima di verificare
                assertThat("At least one new audit event must be generated", countAuditEvents(client), greaterThan(eventCountBefore));
            });

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                GetIndexResponse response = client.admin()
                    .indices()
                    .getIndex(new GetIndexRequest().indices(AUDIT_INDEX_PREFIX + "*"))
                    .actionGet();

                assertThat("At least one audit index matching pattern must exist", response.indices().length, greaterThan(0));

                assertThat(
                    "At least one index must match date pattern: security-auditlog-YYYY.MM.dd",
                    Arrays.stream(response.indices()).anyMatch(name -> name.matches("^security-auditlog-\\d{4}\\.\\d{2}\\.\\d{2}$")),
                    is(true)
                );
            });
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
    public void testPersistsAuditEventsToIndex() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");

            await().atMost(3, SECONDS).pollInterval(100, java.util.concurrent.TimeUnit.MILLISECONDS).untilAsserted(() -> {
                refreshAuditIndices(client); // refresh prima di verificare
                assertThat(
                    "At least 2 new audit events must be generated",
                    countAuditEvents(client) - eventCountBefore,
                    greaterThanOrEqualTo(2L)
                );
            });
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
    public void testReusesExistingIndexWithoutRecreation() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");
            generateAuditEvent("_nodes/stats");

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat(
                    "All generated events must be persisted without errors",
                    countAuditEvents(client) - eventCountBefore,
                    greaterThanOrEqualTo(3L)
                );
            });
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
    public void testAuditDocumentContainsMandatoryFields() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat("Test must generate at least one new event", countAuditEvents(client) - eventCountBefore, greaterThan(0L));
            });

            SearchResponse response = client.search(
                new SearchRequest(AUDIT_INDEX_PREFIX + "*").source(
                    new SearchSourceBuilder().query(QueryBuilders.matchAllQuery())
                        .size(1)
                        .sort("@timestamp", org.opensearch.search.sort.SortOrder.DESC)
                )
            ).actionGet();

            assertThat(
                "At least one audit document must exist",
                Objects.requireNonNull(response.getHits().getTotalHits()).value(),
                greaterThan(0L)
            );

            Map<String, Object> auditDoc = response.getHits().getAt(0).getSourceAsMap();

            assertThat("Missing mandatory field: audit_category", auditDoc.containsKey("audit_category"), is(true));
            assertThat("Missing mandatory field: audit_request_origin", auditDoc.containsKey("audit_request_origin"), is(true));
            assertThat("Missing mandatory field: @timestamp", auditDoc.containsKey("@timestamp"), is(true));
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
    public void testMultipleRequestTypesGenerateAuditEvents() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            try (TestRestClient restClient = cluster.getRestClient(cluster.getAdminCertificate())) {
                restClient.get("_cluster/health");

                String uniqueIndexName = "test-audit-operations-" + System.currentTimeMillis();
                restClient.put(uniqueIndexName);

                StringEntity document = new StringEntity("{\"field\":\"value\"}", ContentType.APPLICATION_JSON);
                restClient.put(uniqueIndexName + "/_doc/1", document, new BasicHeader(HttpHeaders.CONTENT_TYPE, "application/json"));
            }

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat(
                    "Three distinct REST operations must generate at least 3 audit events",
                    countAuditEvents(client) - eventCountBefore,
                    greaterThanOrEqualTo(3L)
                );
            });
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
    public void testIndexFollowsDateBasedNamingPattern() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat("Test must generate at least one new event", countAuditEvents(client) - eventCountBefore, greaterThan(0L));
            });

            await().atMost(3, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                GetIndexResponse indicesResponse = client.admin()
                    .indices()
                    .getIndex(new GetIndexRequest().indices(AUDIT_INDEX_PREFIX + "*"))
                    .actionGet();

                assertThat("At least one audit index must exist", indicesResponse.indices().length, greaterThan(0));

                boolean foundDateBasedIndex = false;
                for (String indexName : indicesResponse.indices()) {
                    if (indexName.matches("^security-auditlog-\\d{4}\\.\\d{2}\\.\\d{2}$")) {
                        foundDateBasedIndex = true;
                        break;
                    }
                }
                assertThat("At least one index must follow pattern: security-auditlog-YYYY.MM.dd", foundDateBasedIndex, is(true));
            });
        }
    }
}
