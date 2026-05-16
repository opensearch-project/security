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

import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.data.TestAlias;
import org.opensearch.test.framework.data.TestIndex;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
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
 * <p>Shared tests ({@code testPersistsAuditEventsToTarget} and
 * {@code testAuditDocumentContainsMandatoryFields}) are inherited from
 * {@link AbstractInternalOpenSearchSinkIntegrationTest}.</p>
 *
 * @see InternalOpenSearchSinkIntegrationTestConcreteIndex for the concrete date-based index variant
 * @see InternalOpenSearchSinkTest for unit tests covering exception and race-condition branches
 */
public class InternalOpenSearchSinkIntegrationTestAuditAlias extends AbstractInternalOpenSearchSinkIntegrationTest {

    private static final String AUDIT_ALIAS = "security-audit-write-alias";
    private static final String BACKING_INDEX = "security-audit-backend-000001";

    static final TestIndex backingIndex = TestIndex.name(BACKING_INDEX).documentCount(0).build();
    static final TestAlias auditAlias = new TestAlias(AUDIT_ALIAS).on(backingIndex).writeIndex(backingIndex);

    @ClassRule
    public static final LocalCluster CLUSTER = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .nodeSettings(Map.of("plugins.security.audit.config.index", AUDIT_ALIAS))
        .internalAudit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(false)))
        .indices(backingIndex)
        .aliases(auditAlias)
        .build();

    @Override
    LocalCluster cluster() {
        return CLUSTER;
    }

    @Override
    String auditTarget() {
        return AUDIT_ALIAS;
    }

    /**
     * The sink must detect that the audit target is an alias and write through it
     * without creating a concrete index with the same name.
     *
     * <p>Generates one event, then checks that the alias still resolves to the
     * backing index and no spurious concrete index was created.</p>
     *
     * <p><b>Tested Code Path:</b> {@code metadata.hasAlias(indexName)} returns
     * {@code true}, so the method logs a debug message and returns {@code true}
     * immediately without attempting index creation.</p>
     */
    @Test
    public void testRecognizesAuditTargetAsWriteAlias() {
        try (TestRestClient client = CLUSTER.getRestClient(CLUSTER.getAdminCertificate())) {
            generateAuditEvent("_cluster/health");

            await().until(() -> {
                HttpResponse countResponse = client.postJson(AUDIT_ALIAS + "/_search", """
                    {"query": {"match_all": {}}, "size": 0}
                    """);
                countResponse.assertStatusCode(200);
                return countResponse.getLongFromJsonBody("/hits/total/value") > 0;
            });

            HttpResponse aliasResponse = client.get("_alias/" + AUDIT_ALIAS);
            aliasResponse.assertStatusCode(200);

            JsonNode aliasBody = aliasResponse.bodyAsJsonNode();
            assertThat("Write alias must exist in cluster metadata", aliasBody.isEmpty(), is(false));

            String concreteIndex = aliasBody.propertyNames().iterator().next();
            assertThat(
                "Alias must resolve to a backing index, not a concrete index with the alias name",
                concreteIndex,
                not(equalTo(AUDIT_ALIAS))
            );

            HttpResponse indexExistsResponse = client.head(concreteIndex);
            assertThat("Backing index must exist physically", indexExistsResponse.getStatusCode(), is(200));
        }
    }
}