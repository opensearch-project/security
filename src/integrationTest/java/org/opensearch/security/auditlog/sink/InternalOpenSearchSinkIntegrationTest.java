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
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.awaitility.Awaitility.await;

/**
 * Integration tests for {@link InternalOpenSearchSink} with default date-based index naming.
 *
 * <p>These tests validate the audit sink behavior when using the default configuration
 * (no custom alias). The default pattern {@code 'security-auditlog-'YYYY.MM.dd} creates
 * daily indices (e.g., {@code security-auditlog-2025.01.11}).</p>
 *
 * <h5>Tested Code Path:</h5>
 * <p>These tests focus on the {@code metadata.hasIndex(indexName)} branch in
 * {@code createIndexIfAbsent()}, validating the regular index creation flow.</p>
 *
 * @see InternalOpenSearchSinkIntegrationTestAuditAlias for alias-specific tests
 */
public class InternalOpenSearchSinkIntegrationTest {

    private static final String AUDIT_INDEX_PREFIX = "security-auditlog-";

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(true)
        .internalAudit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(false)))
        .build();

    private void refreshAuditIndices(Client client) {
        client.admin().indices().prepareRefresh(AUDIT_INDEX_PREFIX + "*").get();
    }

    private void generateAuditEvent(String path) {
        try (TestRestClient restClient = cluster.getRestClient(cluster.getAdminCertificate())) {
            restClient.get(path);
        }
    }

    private long countAuditEvents(Client client) {
        return Objects.requireNonNull(
            client.search(
                new SearchRequest(AUDIT_INDEX_PREFIX + "*").source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(0))
            ).actionGet().getHits().getTotalHits()
        ).value();
    }

    /**
     * Verifies that the audit sink automatically creates a date-based index
     * when the first audit event occurs.
     *
     * <p><b>Tested Code Path:</b> Falls through both {@code metadata.hasAlias()}
     * and {@code metadata.hasIndex()} checks (both return false for new index name),
     * triggering {@code CreateIndexRequest} execution with the date-based index name.</p>
     *
     * <p>This test validates the sink's ability to bootstrap itself on first use
     * without manual index creation.</p>
     */
    @Test
    public void testCreatesAuditIndexAutomatically() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat("At least one new audit event must be generated", countAuditEvents(client), greaterThan(eventCountBefore));
            });

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                GetIndexResponse response = client.admin()
                    .indices()
                    .getIndex(new GetIndexRequest().indices(AUDIT_INDEX_PREFIX + "*"))
                    .actionGet();

                assertThat("At least one audit index must exist", response.indices().length, greaterThan(0));

                assertThat(
                    "All audit indices must follow date-based pattern",
                    Arrays.stream(response.indices()).allMatch(name -> name.matches(AUDIT_INDEX_PREFIX + "\\d{4}\\.\\d{2}\\.\\d{2}$")),
                    is(true)
                );
            });
        }
    }

    /**
     * Verifies that audit events are successfully persisted to the audit index.
     *
     * <p><b>Tested Code Path:</b> On the second event, {@code metadata.hasIndex()}
     * returns true, causing early return without index recreation attempt.</p>
     *
     * <p>This test implicitly validates index reuse behavior. If the second event
     * is persisted successfully, it confirms the sink correctly detected the existing
     * index and did not attempt recreation (which would cause errors).</p>
     */
    @Test
    public void testPersistsAuditEventsToIndex() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat(
                    "At least 2 new audit events must be persisted",
                    countAuditEvents(client) - eventCountBefore,
                    greaterThanOrEqualTo(2L)
                );
            });
        }
    }

    /**
     * Validates that stored audit documents contain all mandatory fields
     * required by the audit log specification.
     *
     * <p><b>Core Fields (all events):</b></p>
     * <ul>
     *   <li>{@code audit_category} - Event classification</li>
     *   <li>{@code audit_request_origin} - Origin layer (REST/TRANSPORT)</li>
     *   <li>{@code @timestamp} - Event timestamp</li>
     * </ul>
     *
     * <p><b>REST-Specific Fields:</b></p>
     * <ul>
     *   <li>{@code audit_rest_request_method} - HTTP method</li>
     *   <li>{@code audit_rest_request_path} - Request path</li>
     * </ul>
     */
    @Test
    public void testAuditDocumentContainsMandatoryFields() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
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
     * Validates that all audit indices follow the configured date-based naming pattern.
     *
     * <p><b>Expected Pattern:</b> {@code security-auditlog-YYYY.MM.dd}</p>
     * <p><b>Examples:</b> {@code security-auditlog-2025.01.21}, {@code security-auditlog-2025.01.22}</p>
     *
     * <p>This naming convention enables:</p>
     * <ul>
     *   <li>Automatic daily index rotation</li>
     *   <li>Simple date-based retention policies</li>
     *   <li>Time-range query optimization</li>
     * </ul>
     *
     * <p><b>Note:</b> This test validates that ALL indices matching the prefix follow
     * the pattern, not just one. This ensures no malformed index names exist.</p>
     */
    @Test
    public void testIndexFollowsDateBasedNamingPattern() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat("Test must generate at least one new event", countAuditEvents(client) - eventCountBefore, greaterThan(0L));
            });

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                GetIndexResponse indicesResponse = client.admin()
                    .indices()
                    .getIndex(new GetIndexRequest().indices(AUDIT_INDEX_PREFIX + "*"))
                    .actionGet();

                assertThat("At least one audit index must exist", indicesResponse.indices().length, greaterThan(0));

                assertThat(
                    "All audit indices must follow pattern: security-auditlog-YYYY.MM.dd",
                    Arrays.stream(indicesResponse.indices())
                        .allMatch(name -> name.matches(AUDIT_INDEX_PREFIX + "\\d{4}\\.\\d{2}\\.\\d{2}$")),
                    is(true)
                );
            });
        }
    }
}
