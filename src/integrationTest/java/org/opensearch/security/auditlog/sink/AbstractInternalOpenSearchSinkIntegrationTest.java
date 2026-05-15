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

import org.junit.Test;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

/**
 * Base class for {@link InternalOpenSearchSink} integration tests.
 *
 * <p>Holds test methods that are valid regardless of whether the audit target
 * is a date-based index or a write alias. Each subclass provides its own
 * {@link org.junit.ClassRule}-annotated {@link LocalCluster} and overrides
 * {@link #cluster()} and {@link #auditTarget()} to supply the correct
 * cluster and query pattern for that configuration variant.</p>
 *
 * <p>Using a shared base class avoids duplicating {@code testPersistsAuditEventsToTarget}
 * and {@code testAuditDocumentContainsMandatoryFields} across the two concrete
 * integration-test classes that differ only in cluster setup.</p>
 *
 * @see InternalOpenSearchSinkIntegrationTest      default date-based index variant
 * @see InternalOpenSearchSinkIntegrationTestAuditAlias  write-alias variant
 */
abstract class AbstractInternalOpenSearchSinkIntegrationTest {

    /**
     * Returns the cluster configured for this test variant.
     * Implementations must expose the {@code @ClassRule}-annotated cluster field.
     */
    abstract LocalCluster cluster();

    /**
     * Returns the index name or alias used to query audit documents.
     *
     * <p>Examples:</p>
     * <ul>
     *   <li>{@code "security-auditlog-*"} — default date-based variant</li>
     *   <li>{@code "security-audit-write-alias"} — alias variant</li>
     * </ul>
     */
    abstract String auditTarget();

    // -----------------------------------------------------------------------
    // Shared helpers
    // -----------------------------------------------------------------------

    /** Counts all audit documents reachable through {@link #auditTarget()}. */
    long countAuditDocs(Client client) {
        return Objects.requireNonNull(
            client.search(
                new SearchRequest(auditTarget())
                    .source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(0))
            ).actionGet().getHits().getTotalHits()
        ).value();
    }

    /** Refreshes the audit target so newly indexed documents become searchable. */
    void refreshAuditTarget(Client client) {
        client.admin().indices().prepareRefresh(auditTarget()).get();
    }

    /** Issues an authenticated REST GET that triggers one {@code GRANTED_PRIVILEGES} audit event. */
    void generateAuditEvent(String path) {
        try (TestRestClient restClient = cluster().getRestClient(cluster().getAdminCertificate())) {
            restClient.get(path);
        }
    }

    // -----------------------------------------------------------------------
    // Shared tests — valid for both date-based index and alias configurations
    // -----------------------------------------------------------------------

    /**
     * Verifies that multiple audit events are successfully persisted to the audit target.
     *
     * <p><b>Tested Code Path:</b> From the second event onward,
     * {@code createIndexIfAbsent()} detects the target already exists
     * (via {@code metadata.hasIndex()} for concrete indices or
     * {@code metadata.hasAlias()} for aliases) and returns {@code true}
     * without attempting recreation. Successful persistence of both events
     * confirms the early-return branch works correctly.</p>
     */
    @Test
    public void testPersistsAuditEventsToTarget() {
        try (Client client = cluster().getInternalNodeClient()) {
            long before = countAuditDocs(client);

            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditTarget(client);
                assertThat("At least 2 new audit events must be persisted",
                    countAuditDocs(client) - before, greaterThanOrEqualTo(2L));
            });
        }
    }

    /**
     * Validates that audit documents contain all mandatory fields defined by the
     * audit log specification.
     *
     * <p><b>Core Fields (all events):</b></p>
     * <ul>
     *   <li>{@code audit_category} — event classification (e.g., {@code GRANTED_PRIVILEGES})</li>
     *   <li>{@code audit_request_layer} — processing layer; expected value: {@code REST}</li>
     *   <li>{@code audit_request_origin} — origin layer; expected value: {@code REST}</li>
     *   <li>{@code @timestamp} — ISO-8601 event timestamp</li>
     * </ul>
     *
     * <p><b>REST-Specific Fields:</b></p>
     * <ul>
     *   <li>{@code audit_rest_request_method} — HTTP method (e.g., {@code GET})</li>
     *   <li>{@code audit_rest_request_path} — request path (e.g., {@code /_cluster/health})</li>
     * </ul>
     *
     * <p><b>Absent Fields (transport audit disabled):</b></p>
     * <ul>
     *   <li>{@code audit_transport_request_type} — must not be present</li>
     * </ul>
     */
    @Test
    public void testAuditDocumentContainsMandatoryFields() {
        try (Client client = cluster().getInternalNodeClient()) {
            long before = countAuditDocs(client);

            generateAuditEvent("_cluster/health");

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).untilAsserted(() -> {
                refreshAuditTarget(client);
                assertThat("Test must generate at least one new event",
                    countAuditDocs(client) - before, greaterThan(0L));
            });

            SearchResponse response = client.search(
                new SearchRequest(auditTarget()).source(
                    new SearchSourceBuilder()
                        .query(QueryBuilders.matchAllQuery())
                        .size(1)
                        .sort("@timestamp", SortOrder.DESC)
                )
            ).actionGet();

            assertThat("At least one audit document must exist",
                Objects.requireNonNull(response.getHits().getTotalHits()).value(), greaterThan(0L));

            Map<String, Object> doc = response.getHits().getAt(0).getSourceAsMap();

            assertThat("Missing field: audit_category",
                doc.containsKey("audit_category"), is(true));
            assertThat("Missing field: audit_request_layer",
                doc.containsKey("audit_request_layer"), is(true));
            assertThat("Wrong value: audit_request_layer",
                doc.get("audit_request_layer"), is("REST"));
            assertThat("Missing field: audit_request_origin",
                doc.containsKey("audit_request_origin"), is(true));
            assertThat("Wrong value: audit_request_origin",
                doc.get("audit_request_origin"), is("REST"));
            assertThat("Missing field: @timestamp",
                doc.containsKey("@timestamp"), is(true));
            assertThat("Missing field: audit_rest_request_method",
                doc.containsKey("audit_rest_request_method"), is(true));
            assertThat("Missing field: audit_rest_request_path",
                doc.containsKey("audit_rest_request_path"), is(true));
            assertThat("Unexpected field: audit_transport_request_type",
                doc.containsKey("audit_transport_request_type"), is(false));
        }
    }
}
