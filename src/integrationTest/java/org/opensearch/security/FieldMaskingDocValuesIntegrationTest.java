/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file to be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.MaskedField;
import org.opensearch.security.configuration.Salt;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.junit.Assert.assertEquals;

@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class FieldMaskingDocValuesIntegrationTest {
    private static final String INDEX_PATTERN = "masked-doc-values-*";
    private static final String SALT = "fieldmasktestsalt";
    private static final TestSecurityConfig.User ADMIN = new TestSecurityConfig.User("admin").roles(TestSecurityConfig.Role.ALL_ACCESS);
    private static final TestSecurityConfig.User FULL = new TestSecurityConfig.User("full").roles(
        new TestSecurityConfig.Role("full").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").on(INDEX_PATTERN)
    );
    private static final TestSecurityConfig.User MASKED = new TestSecurityConfig.User("masked").roles(
        new TestSecurityConfig.Role("masked").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .maskedFields("secret")
            .on(INDEX_PATTERN)
    );
    private static final TestSecurityConfig.User INCLUDED = new TestSecurityConfig.User("included").roles(
        new TestSecurityConfig.Role("included").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .fls("secret")
            .maskedFields("secret")
            .on(INDEX_PATTERN)
    );
    private static final TestSecurityConfig.User HIDDEN = new TestSecurityConfig.User("hidden").roles(
        new TestSecurityConfig.Role("hidden").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .fls("~secret", "~timestamp")
            .maskedFields("secret")
            .on(INDEX_PATTERN)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN, FULL, MASKED, INCLUDED, HIDDEN)
        .nodeSettings(Map.of("plugins.security.compliance.salt", SALT, "plugins.security.masked_fields.algorithm.default", "SHA-256"))
        .build();

    @ParametersFactory
    public static Collection<Object[]> parameters() {
        return List.of(
            new Object[] { FULL, false },
            new Object[] { FULL, true },
            new Object[] { MASKED, false },
            new Object[] { MASKED, true },
            new Object[] { INCLUDED, false },
            new Object[] { INCLUDED, true },
            new Object[] { HIDDEN, false },
            new Object[] { HIDDEN, true }
        );
    }

    private final TestSecurityConfig.User user;
    private final boolean deleted;

    public FieldMaskingDocValuesIntegrationTest(TestSecurityConfig.User user, boolean deleted) {
        this.user = user;
        this.deleted = deleted;
    }

    @BeforeClass
    public static void createIndices() {
        try (TestRestClient client = cluster.getRestClient(ADMIN)) {
            for (boolean deleted : List.of(false, true)) {
                String index = indexName(deleted);
                client.putJson(
                    index,
                    "{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},"
                        + "\"mappings\":{\"properties\":{\"secret\":{\"type\":\"keyword\"},"
                        + "\"timestamp\":{\"type\":\"date\"}}}}"
                ).assertStatusCode(200);
                List<String> values = List.of("alpha", "beta", "alpha", "gamma");
                for (int i = 0; i < values.size(); i++) {
                    client.putJson(index + "/_doc/" + i, "{\"secret\":\"" + values.get(i) + "\",\"timestamp\":0}").assertStatusCode(201);
                }
                client.putJson(index + "/_doc/missing", "{}").assertStatusCode(201);
                client.post(index + "/_refresh").assertStatusCode(200);
                if (deleted) {
                    client.delete(index + "/_doc/3?refresh=true").assertStatusCode(200);
                }
            }
        }
    }

    @Test
    public void existsCountsAgreeWithSearch() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            for (String field : List.of("secret", "timestamp", "absent")) {
                boolean visible = !field.equals("absent") && user != HIDDEN && (!field.equals("timestamp") || user != INCLUDED);
                int expected = visible ? (deleted ? 3 : 4) : 0;
                String query = "{\"query\":{\"exists\":{\"field\":\"" + field + "\"}}}";
                var count = client.postJson(indexName(deleted) + "/_count", query);
                count.assertStatusCode(200);
                assertEquals(field, expected, count.getIntFromJsonBody("/count"));
                for (int size : List.of(0, 10)) {
                    var search = client.postJson(indexName(deleted) + "/_search?size=" + size + "&track_total_hits=true", query);
                    search.assertStatusCode(200);
                    assertEquals(field, expected, search.getIntFromJsonBody("/hits/total/value"));
                    assertEquals(field, size == 0 ? 0 : expected, search.bodyAsJsonNode().at("/hits/hits").size());
                }
            }
        }
    }

    @Test
    public void aggregationsUseOnlyVisibleProtectedValues() throws Exception {
        try (TestRestClient client = cluster.getRestClient(user)) {
            var response = client.postJson(
                indexName(deleted) + "/_search",
                "{\"size\":0,\"aggs\":{"
                    + "\"terms\":{\"terms\":{\"field\":\"secret\"}},"
                    + "\"cardinality\":{\"cardinality\":{\"field\":\"secret\"}},"
                    + "\"dates\":{\"date_histogram\":{\"field\":\"timestamp\",\"fixed_interval\":\"1d\"}}}}"
            );
            response.assertStatusCode(200);
            Set<String> expected = user == HIDDEN ? Set.of() : deleted ? Set.of("alpha", "beta") : Set.of("alpha", "beta", "gamma");
            if (user == MASKED || user == INCLUDED) {
                MaskedField masking = new MaskedField(
                    "secret",
                    Salt.from(Settings.builder().put("plugins.security.compliance.salt", SALT).build()),
                    "SHA-256"
                );
                expected = expected.stream().map(masking::mask).collect(Collectors.toSet());
            }
            Set<String> actual = new HashSet<>();
            response.bodyAsJsonNode().at("/aggregations/terms/buckets").forEach(bucket -> actual.add(bucket.get("key").asText()));
            assertEquals(expected, actual);
            assertEquals(expected.size(), response.getIntFromJsonBody("/aggregations/cardinality/value"));
            int expectedDates = user == HIDDEN || user == INCLUDED ? 0 : 1;
            assertEquals(expectedDates, response.bodyAsJsonNode().at("/aggregations/dates/buckets").size());
            if (expectedDates != 0) {
                assertEquals(deleted ? 3 : 4, response.getIntFromJsonBody("/aggregations/dates/buckets/0/doc_count"));
            }
        }
    }

    private static String indexName(boolean deleted) {
        return "masked-doc-values-" + (deleted ? "deleted" : "live");
    }
}
