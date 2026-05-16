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

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.admin.indices.get.GetIndexRequest;
import org.opensearch.action.admin.indices.get.GetIndexResponse;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.client.Client;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

/**
 * Integration tests for {@link InternalOpenSearchSink} with a plain concrete index
 * (no alias configured).
 *
 * <p>Exercises the regular index creation path: the default pattern
 * {@code 'security-auditlog-'YYYY.MM.dd} produces daily indices
 * (e.g., {@code security-auditlog-2025.01.11}). No pre-existing index or alias is
 * present when the cluster starts, so the sink must create the index on first write.</p>
 *
 * <h5>Tested Code Paths in {@code createIndexIfAbsent()}:</h5>
 * <ul>
 *   <li>First event: both {@code metadata.hasAlias()} and {@code metadata.hasIndex()} return
 *       {@code false}, triggering a {@code CreateIndexRequest} with the date-based index name
 *       ({@link #testCreatesAuditIndexAutomatically()}).</li>
 *   <li>Subsequent events: {@code metadata.hasIndex()} returns {@code true}; covered by
 *       the inherited {@link AbstractInternalOpenSearchSinkIntegrationTest#testPersistsAuditEventsToTarget()}.</li>
 * </ul>
 *
 * <p>Shared tests ({@code testPersistsAuditEventsToTarget} and
 * {@code testAuditDocumentContainsMandatoryFields}) are inherited from
 * {@link AbstractInternalOpenSearchSinkIntegrationTest}.</p>
 *
 * @see InternalOpenSearchSinkIntegrationTestAuditAlias for the write-alias variant
 * @see InternalOpenSearchSinkTest for unit tests covering exception and race-condition branches
 */
public class InternalOpenSearchSinkIntegrationTestConcreteIndex extends AbstractInternalOpenSearchSinkIntegrationTest {

    private static final String AUDIT_INDEX_PREFIX = "security-auditlog-";

    @ClassRule
    public static final LocalCluster CLUSTER = new LocalCluster.Builder()
        .clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(true)
        .internalAudit(new AuditConfiguration(true)
            .filters(new AuditFilters().enabledRest(true).enabledTransport(false)))
        .build();

    @Override
    LocalCluster cluster() {
        return CLUSTER;
    }

    @Override
    String auditTarget() {
        return AUDIT_INDEX_PREFIX + "*";
    }

    /**
     * Verifies that the audit sink automatically creates a date-based index
     * on the first audit event.
     *
     * <p><b>Tested Code Path:</b> Both {@code metadata.hasAlias()} and
     * {@code metadata.hasIndex()} return {@code false} for a brand-new index name,
     * so {@code CreateIndexRequest} is executed. The resulting index name must
     * match the pattern {@code security-auditlog-YYYY.MM.dd}
     * (e.g., {@code security-auditlog-2025.01.11}).</p>
     */
    @Test
    public void testCreatesAuditIndexAutomatically() {
        try (Client client = CLUSTER.getInternalNodeClient()) {
            long before = countAuditDocs(client);

            generateAuditEvent("_cluster/health");

            await().atMost(10, SECONDS).pollInterval(200, MILLISECONDS).untilAsserted(() -> {
                refreshAuditTarget(client);
                assertThat("At least one new audit event must be generated",
                    countAuditDocs(client), greaterThan(before));
            });

            await().atMost(10, SECONDS).pollInterval(200, MILLISECONDS).untilAsserted(() -> {
                GetIndexResponse response = client
                    .admin()
                    .indices()
                    .getIndex(new GetIndexRequest().indices(AUDIT_INDEX_PREFIX + "*"))
                    .actionGet();

                assertThat("At least one audit index must exist",
                    response.indices().length, greaterThan(0));
                assertThat("All audit indices must follow date-based pattern security-auditlog-YYYY.MM.dd",
                    Arrays.stream(response.indices())
                        .allMatch(name -> name.matches(AUDIT_INDEX_PREFIX + "\\d{4}\\.\\d{2}\\.\\d{2}$")),
                    is(true));
            });
        }
    }
}