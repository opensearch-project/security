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
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.collection.IsMapContaining.hasKey;
import static org.awaitility.Awaitility.await;

/**
 * Integration tests for {@link InternalOpenSearchSink} with write-alias–based configuration.
 *
 * <p>These tests validate the audit sink behavior when a preconfigured write alias
 * is used instead of a concrete index name. In this setup, the audit sink must
 * detect that the target name is an alias and avoid attempting index creation.</p>
 *
 * <h5>Tested Code Path:</h5>
 * <p>These tests focus on the {@code metadata.hasAlias(indexName)} branch in
 * {@code createIndexIfAbsent()}, ensuring that alias targets are correctly
 * recognized and accepted.</p>
 *
 * <p>This behavior is required to support Index Lifecycle Management (ILM)
 * patterns where a write alias points to a rolling series of indices.</p>
 *
 * @see InternalOpenSearchSinkIntegrationTest for regular index-based tests
 */
public class InternalOpenSearchSinkIntegrationTestAuditAlias {

    private static final String AUDIT_ALIAS = "security-audit-write-alias";
    private static final String BACKING_INDEX = "security-audit-backend-000001";

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(true)
        .nodeSettings(Map.of("plugins.security.audit.config.index", AUDIT_ALIAS))
        .internalAudit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(false)))
        .build();

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

    private long countAuditDocs(Client client) {
        SearchResponse response = client.search(
            new SearchRequest(AUDIT_ALIAS).source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(0))
        ).actionGet();

        return Objects.requireNonNull(response.getHits().getTotalHits()).value();
    }

    private void generateAuditEvent(String path) {
        try (TestRestClient restClient = cluster.getRestClient(cluster.getAdminCertificate())) {
            restClient.get(path);
        }
    }

    /**
     * Tests the core functionality of the alias detection change.
     *
     * <p><b>Validates:</b> The {@code metadata.hasAlias(indexName)} branch correctly
     * identifies the audit target as an alias and returns true without attempting
     * index creation.</p>
     *
     * <p><b>Without this change:</b> The sink would try to create an index named
     * {@code security-audit-write-alias}, which would fail because an alias with
     * that name already exists.</p>
     */
    @Test
    public void testRecognizesAuditTargetAsWriteAlias() {
        try (Client client = cluster.getInternalNodeClient()) {
            generateAuditEvent("_cluster/health");

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).until(() -> countAuditDocs(client) > 0);

            GetAliasesResponse aliasesResponse = client.admin().indices().getAliases(new GetAliasesRequest(AUDIT_ALIAS)).actionGet();

            assertThat("Write alias must exist in cluster metadata", aliasesResponse.getAliases().isEmpty(), is(false));

            String concreteIndex = aliasesResponse.getAliases().keySet().iterator().next();
            assertThat("Alias must resolve to a backing index", concreteIndex, not(equalTo(AUDIT_ALIAS)));

            boolean backendIndexExists = client.admin().indices().exists(new IndicesExistsRequest(concreteIndex)).actionGet().isExists();

            assertThat("Backing index must exist physically", backendIndexExists, is(true));
        }
    }

    /**
     * Tests that audit events are successfully written through the alias.
     *
     * <p><b>Validates:</b> The sink writes events to the alias, which OpenSearch
     * routes to the write index. Multiple events accumulate correctly.</p>
     */
    @Test
    public void testWritesEventsToAliasSuccessfully() {
        try (Client client = cluster.getInternalNodeClient()) {
            long before = countAuditDocs(client);

            generateAuditEvent("_cluster/health");
            generateAuditEvent("_cluster/stats");
            generateAuditEvent("_nodes/info");

            await().atMost(10, SECONDS).pollInterval(100, MILLISECONDS).until(() -> countAuditDocs(client) - before >= 3);

            long after = countAuditDocs(client);
            assertThat("Multiple events must be written through alias", after - before, greaterThan(2L));
        }
    }

    /**
     * Verifies that audit documents written via a write alias contain all mandatory fields
     * and do not include irrelevant fields.
     *
     * <p><b>Validates:</b> When an audit event is generated and routed through a write alias,
     * the resulting document contains the required fields:
     * <ul>
     *     <li>audit_category</li>
     *     <li>audit_request_origin</li>
     *     <li>@timestamp</li>
     *     <li>audit_rest_request_method</li>
     *     <li>audit_rest_request_path</li>
     *     <li>audit_request_layer</li>
     * </ul>
     * and does not include the transport-specific field audit_transport_request_type.</p>
     *
     * <p><b>Why it's important:</b> This ensures that using a write alias does not alter
     * the content or structure of audit documents, preserving compliance and correctness.</p>
     *
     * <p><b>Test coverage:</b> Confirms that documents routed via aliases maintain
     * expected audit fields and values (REST events only).</p>
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
}
