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

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.data.TestAlias;
import org.opensearch.test.framework.data.TestIndex;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.awaitility.Awaitility.await;

/**
 * Integration tests for the {@code metadata.hasAlias(indexName)} branch in
 * {@link InternalOpenSearchSink#createIndexIfAbsent(String)}.
 *
 * <p>The backing index and write alias are pre-created via the {@link LocalCluster.Builder}
 * (transport audit is disabled to avoid race conditions during setup).
 * Tests share a single cluster and use a before/after delta pattern so that
 * execution order does not matter.</p>
 *
 */
public class InternalOpenSearchSinkIntegrationTestAuditAlias {

    private static final String AUDIT_ALIAS = "security-audit-write-alias";
    private static final String BACKING_INDEX = "security-audit-backend-000001";

    static final TestIndex backingIndex = TestIndex.name(BACKING_INDEX).documentCount(0).build();
    static final TestAlias auditAlias = new TestAlias(AUDIT_ALIAS).on(backingIndex).writeIndex(backingIndex);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .nodeSettings(Map.of("plugins.security.audit.config.index", AUDIT_ALIAS))
        .internalAudit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(false)))
        .indices(backingIndex)
        .aliases(auditAlias)
        .build();

    /** Counts all audit documents reachable through the write alias. */
    private long countAuditDocs(TestRestClient client) {
        HttpResponse response = client.postJson(AUDIT_ALIAS + "/_search", """
            {"query": {"match_all": {}}, "size": 0}
            """);
        response.assertStatusCode(200);
        return response.getLongFromJsonBody("/hits/total/value");
    }

    /** Issues an authenticated REST GET that triggers an {@code AUTHENTICATED} audit event. */
    private void generateAuditEvent(String path) {
        try (TestRestClient restClient = cluster.getRestClient(cluster.getAdminCertificate())) {
            restClient.get(path);
        }
    }

    /**
     * The sink must detect that the audit target is an alias and write through it
     * without creating a concrete index with the same name.
     *
     * <p>Generates one event, then checks that the alias still resolves to the
     * backing index and no spurious concrete index was created.</p>
     */
    @Test
    public void testRecognizesAuditTargetAsWriteAlias() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            generateAuditEvent("_cluster/health");

            await().until(() -> countAuditDocs(client) > 0);

            HttpResponse aliasResponse = client.get("_alias/" + AUDIT_ALIAS);
            aliasResponse.assertStatusCode(200);

            JsonNode aliasBody = aliasResponse.bodyAsJsonNode();
            assertThat("Write alias must exist in cluster metadata", aliasBody.isEmpty(), is(false));

            String concreteIndex = aliasBody.fieldNames().next();
            assertThat(
                "Alias must resolve to a backing index, not a concrete index with the alias name",
                concreteIndex,
                not(equalTo(AUDIT_ALIAS))
            );

            HttpResponse indexExistsResponse = client.head(concreteIndex);
            assertThat("Backing index must exist physically", indexExistsResponse.getStatusCode(), is(200));
        }
    }

    /**
     * The alias branch is invoked on every {@code doStore} call.
     * Generates three distinct events and asserts all are persisted, confirming
     * that repeated writes through the alias succeed.
     */
    @Test
    public void testWritesEventsToAliasSuccessfully() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            long before = countAuditDocs(client);

            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");
            generateAuditEvent("_nodes/info");

            await().untilAsserted(
                () -> assertThat("At least 3 events must be written through alias", countAuditDocs(client) - before, greaterThan(2L))
            );
        }
    }

    /**
     * Documents written via the alias must contain the same mandatory audit fields
     * as those written to a concrete index (category, timestamp, REST method/path,
     * layer and origin). Transport-specific fields must be absent since transport
     * audit is disabled.
     */
    @Test
    public void testAuditDocumentsViaAliasContainMandatoryFields() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            long before = countAuditDocs(client);
            generateAuditEvent("_cluster/health");

            await().until(() -> countAuditDocs(client) > before);

            HttpResponse response = client.postJson(AUDIT_ALIAS + "/_search", """
                {"query": {"match_all": {}}, "size": 1, "sort": [{"@timestamp": "desc"}]}
                """);
            response.assertStatusCode(200);

            JsonNode source = response.bodyAsJsonNode().get("hits").get("hits").get(0).get("_source");

            assertThat(source.has("audit_category"), is(true));
            assertThat(source.has("@timestamp"), is(true));
            assertThat(source.has("audit_rest_request_method"), is(true));
            assertThat(source.has("audit_rest_request_path"), is(true));
            assertThat(source.get("audit_request_layer").asText(), is("REST"));
            assertThat(source.get("audit_request_origin").asText(), is("REST"));
            assertThat(source.has("audit_transport_request_type"), is(false));
        }
    }
}
