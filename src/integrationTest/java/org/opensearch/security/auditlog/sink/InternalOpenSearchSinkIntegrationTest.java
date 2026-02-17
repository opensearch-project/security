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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasKey;
import static org.awaitility.Awaitility.await;

/**
 * Integration tests for {@link InternalOpenSearchSink} with default date-based index naming.
 *
 * <p>These tests validate the audit sink behavior when using the default configuration
 * (no custom alias). The default pattern {@code 'security-auditlog-'YYYY.MM.dd} creates
 * daily indices (e.g., {@code security-auditlog-2025.01.11}).</p>
 *
 * <h5>Tested Code Path:</h5>
 * <p>These tests exercise the regular index flow in {@code createIndexIfAbsent()}:
 * both the {@code CreateIndexRequest} branch (when the index does not yet exist)
 * and the {@code metadata.hasIndex(indexName)} early-return branch (when it already exists).</p>
 *
 * @see InternalOpenSearchSinkIntegrationTestAuditAlias for alias-specific tests
 */
public class InternalOpenSearchSinkIntegrationTest {

    private static final String AUDIT_INDEX_PREFIX = "security-auditlog-";
    private static final String AUDIT_INDEX_WILDCARD = AUDIT_INDEX_PREFIX + "*";
    private static final String AUDIT_INDEX_DATE_REGEX = AUDIT_INDEX_PREFIX + "\\d{4}\\.\\d{2}\\.\\d{2}$";

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .internalAudit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(false)))
        .build();

    private void refreshAuditIndices(Client client) {
        client.admin().indices().prepareRefresh(AUDIT_INDEX_WILDCARD).get();
    }

    private void generateAuditEvent(String path) {
        try (TestRestClient restClient = cluster.getRestClient(cluster.getAdminCertificate())) {
            restClient.get(path);
        }
    }

    private long countAuditEvents(Client client) {
        return client.search(
            new SearchRequest(AUDIT_INDEX_WILDCARD).source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(0))
        ).actionGet().getHits().getTotalHits().value();
    }

    /**
     * Verifies that the audit sink automatically creates a date-based index
     * when an audit event targets a not-yet-created index.
     *
     * <p><b>Tested Code Path:</b> Both {@code metadata.hasAlias()} and
     * {@code metadata.hasIndex()} return false for the date-based index name,
     * triggering the {@code CreateIndexRequest} execution.</p>
     *
     * <p>This test validates the sink's ability to bootstrap itself
     * without requiring manual index creation.</p>
     */
    @Test
    public void testCreatesAuditIndexAutomatically() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");

            await().untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat("At least one new audit event must be generated", countAuditEvents(client), greaterThan(eventCountBefore));
            });

            await().untilAsserted(() -> {
                GetIndexResponse response = client.admin()
                    .indices()
                    .getIndex(new GetIndexRequest().indices(AUDIT_INDEX_WILDCARD))
                    .actionGet();

                assertThat("At least one audit index must exist", response.indices().length, greaterThan(0));

                assertThat(
                    "All audit indices must follow date-based pattern",
                    Arrays.stream(response.indices()).allMatch(name -> name.matches(AUDIT_INDEX_DATE_REGEX)),
                    is(true)
                );
            });
        }
    }

    /**
     * Verifies that multiple audit events are successfully persisted to the audit index.
     *
     * <p><b>Tested Code Path:</b> When the date-based index already exists,
     * {@code metadata.hasIndex()} returns true, causing an early return
     * without attempting index recreation.</p>
     *
     * <p>This test implicitly validates index reuse behavior: if both events
     * are persisted successfully, the sink correctly detected the existing index
     * and wrote to it without errors.</p>
     */
    @Test
    public void testPersistsAuditEventsToIndex() {
        try (Client client = cluster.getInternalNodeClient()) {
            long eventCountBefore = countAuditEvents(client);

            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");

            await().untilAsserted(() -> {
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

            await().untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat("Test must generate at least one new event", countAuditEvents(client) - eventCountBefore, greaterThan(0L));
            });

            SearchResponse response = client.search(
                new SearchRequest(AUDIT_INDEX_WILDCARD).source(
                    new SearchSourceBuilder().query(QueryBuilders.matchAllQuery())
                        .size(1)
                        .sort("@timestamp", org.opensearch.search.sort.SortOrder.DESC)
                )
            ).actionGet();

            assertThat("At least one audit document must exist", response.getHits().getTotalHits().value(), greaterThan(0L));

            Map<String, Object> auditDoc = response.getHits().getAt(0).getSourceAsMap();

            assertThat(auditDoc, hasKey("audit_category"));
            assertThat(auditDoc, hasKey("audit_request_origin"));
            assertThat(auditDoc, hasKey("@timestamp"));
            assertThat(auditDoc, hasKey("audit_rest_request_method"));
            assertThat(auditDoc, hasKey("audit_rest_request_path"));
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

            await().untilAsserted(() -> {
                refreshAuditIndices(client);
                assertThat("Test must generate at least one new event", countAuditEvents(client) - eventCountBefore, greaterThan(0L));
            });

            await().untilAsserted(() -> {
                GetIndexResponse indicesResponse = client.admin()
                    .indices()
                    .getIndex(new GetIndexRequest().indices(AUDIT_INDEX_WILDCARD))
                    .actionGet();

                assertThat("At least one audit index must exist", indicesResponse.indices().length, greaterThan(0));

                assertThat(
                    "All audit indices must follow pattern: security-auditlog-YYYY.MM.dd",
                    Arrays.stream(indicesResponse.indices()).allMatch(name -> name.matches(AUDIT_INDEX_DATE_REGEX)),
                    is(true)
                );
            });
        }
    }
}
