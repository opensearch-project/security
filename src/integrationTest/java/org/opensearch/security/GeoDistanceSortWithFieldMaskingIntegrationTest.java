/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file to be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.JsonNode;
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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * A search sorted by _geo_distance with a non-default "unit" as the first sort key makes Lucene call
 * getPointValues with a null field name. That call goes through DlsFlsFilterLeafReader, which must not throw,
 * and the search must still return correctly sorted, correctly masked results.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GeoDistanceSortWithFieldMaskingIntegrationTest {
    private static final String INDEX = "places-v1";
    private static final String SALT = "geosortmasksalt16";
    private static final double EARTH_MEAN_RADIUS_METERS = 6371008.7714;
    private static final double METERS_PER_MILE = 1609.344;
    private static final double ORIGIN_LAT = 47.6;
    private static final double ORIGIN_LON = -122.3;

    // id, latitude, owner, rank; all documents share the origin's longitude and status "active"
    private static final List<Object[]> DOCS = List.of(
        new Object[] { "far", 48.0, "carol", 3 },
        new Object[] { "near", 47.6, "alice", 1 },
        new Object[] { "mid", 47.7, "bob", 2 }
    );
    private static final List<String> IDS_BY_DISTANCE = List.of("near", "mid", "far");
    private static final List<String> IDS_BY_DISTANCE_DESC = List.of("far", "mid", "near");

    private static final TestSecurityConfig.User ADMIN = new TestSecurityConfig.User("admin").roles(TestSecurityConfig.Role.ALL_ACCESS);
    // all_access role, no DLS, FLS or masking
    private static final TestSecurityConfig.User ALL_ACCESS = new TestSecurityConfig.User("all_access_user").roles(
        TestSecurityConfig.Role.ALL_ACCESS
    );
    // read access only, no DLS, FLS or masking
    private static final TestSecurityConfig.User PLAIN = new TestSecurityConfig.User("plain").roles(
        new TestSecurityConfig.Role("plain").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").on(INDEX)
    );
    // masking with an exact field name
    private static final TestSecurityConfig.User MASKED_EXACT = new TestSecurityConfig.User("masked_exact").roles(
        new TestSecurityConfig.Role("masked_exact").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .maskedFields("owner")
            .on(INDEX)
    );
    // masking with a wildcard pattern
    private static final TestSecurityConfig.User MASKED_WILDCARD = new TestSecurityConfig.User("masked_wildcard").roles(
        new TestSecurityConfig.Role("masked_wildcard").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .maskedFields("own*")
            .on(INDEX)
    );
    // FLS in exclude mode and masking
    private static final TestSecurityConfig.User FLS_EXCLUDE_AND_MASKED = new TestSecurityConfig.User("fls_exclude_and_masked").roles(
        new TestSecurityConfig.Role("fls_exclude_and_masked").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .fls("~status")
            .maskedFields("owner")
            .on(INDEX)
    );
    // FLS in include mode and masking
    private static final TestSecurityConfig.User FLS_INCLUDE_AND_MASKED = new TestSecurityConfig.User("fls_include_and_masked").roles(
        new TestSecurityConfig.Role("fls_include_and_masked").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .fls("location", "owner")
            .maskedFields("owner")
            .on(INDEX)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN, ALL_ACCESS, PLAIN, MASKED_EXACT, MASKED_WILDCARD, FLS_EXCLUDE_AND_MASKED, FLS_INCLUDE_AND_MASKED)
        .nodeSettings(Map.of("plugins.security.compliance.salt", SALT, "plugins.security.masked_fields.algorithm.default", "SHA-256"))
        .build();

    @ParametersFactory
    public static Collection<Object[]> parameters() {
        return List.of(
            new Object[] { ALL_ACCESS },
            new Object[] { PLAIN },
            new Object[] { MASKED_EXACT },
            new Object[] { MASKED_WILDCARD },
            new Object[] { FLS_EXCLUDE_AND_MASKED },
            new Object[] { FLS_INCLUDE_AND_MASKED }
        );
    }

    private final TestSecurityConfig.User user;

    public GeoDistanceSortWithFieldMaskingIntegrationTest(TestSecurityConfig.User user) {
        this.user = user;
    }

    @BeforeClass
    public static void createIndex() {
        try (TestRestClient client = cluster.getRestClient(ADMIN)) {
            client.putJson(
                INDEX,
                "{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},"
                    + "\"mappings\":{\"properties\":{\"location\":{\"type\":\"geo_point\"},"
                    + "\"status\":{\"type\":\"keyword\"},\"owner\":{\"type\":\"keyword\"},\"rank\":{\"type\":\"integer\"}}}}"
            ).assertStatusCode(200);
            for (Object[] doc : DOCS) {
                client.putJson(
                    INDEX + "/_doc/" + doc[0],
                    "{\"location\":{\"lat\":"
                        + doc[1]
                        + ",\"lon\":"
                        + ORIGIN_LON
                        + "},\"status\":\"active\",\"owner\":\""
                        + doc[2]
                        + "\",\"rank\":"
                        + doc[3]
                        + "}"
                ).assertStatusCode(201);
            }
            client.post(INDEX + "/_refresh").assertStatusCode(200);
        }
    }

    @Test
    public void geoDistanceSortWithUnitAsFirstKey() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            var response = client.postJson(INDEX + "/_search", "{\"sort\":[" + geoSort("\"unit\":\"mi\",") + "]}");
            response.assertStatusCode(200);
            assertHits(response.bodyAsJsonNode(), 0, METERS_PER_MILE, IDS_BY_DISTANCE);
        }
    }

    @Test
    public void geoDistanceSortWithoutUnit() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            var response = client.postJson(INDEX + "/_search", "{\"sort\":[" + geoSort("") + "]}");
            response.assertStatusCode(200);
            assertHits(response.bodyAsJsonNode(), 0, 1, IDS_BY_DISTANCE);
        }
    }

    @Test
    public void geoDistanceSortWithUnitAsSecondKey() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            var response = client.postJson(
                INDEX + "/_search",
                "{\"sort\":[{\"status\":{\"order\":\"asc\"}}," + geoSort("\"unit\":\"mi\",") + "]}"
            );
            response.assertStatusCode(200);
            assertHits(response.bodyAsJsonNode(), 1, METERS_PER_MILE, IDS_BY_DISTANCE);
        }
    }

    @Test
    public void geoDistanceSortDescendingWithoutUnit() {
        try (TestRestClient client = cluster.getRestClient(user)) {
            var response = client.postJson(INDEX + "/_search", "{\"sort\":[" + geoSort(originPoint(), "\"order\":\"desc\"") + "]}");
            response.assertStatusCode(200);
            assertHits(response.bodyAsJsonNode(), 0, 1, IDS_BY_DISTANCE_DESC);
        }
    }

    @Test
    public void geoDistanceSortWithTwoOriginPointsWithoutUnit() {
        // With mode "min" (the default for ascending order), each document's distance is to the nearer origin point.
        // The second point is far from all documents, so the expected distances are to the first point.
        try (TestRestClient client = cluster.getRestClient(user)) {
            var response = client.postJson(
                INDEX + "/_search",
                "{\"sort\":[" + geoSort("[" + originPoint() + ",{\"lat\":0,\"lon\":0}]", "\"order\":\"asc\"") + "]}"
            );
            response.assertStatusCode(200);
            assertHits(response.bodyAsJsonNode(), 0, 1, IDS_BY_DISTANCE);
        }
    }

    @Test
    public void termsAggregationWithMissingOnKeyword() {
        assertTermsAggregationWithMissing("status", "\"__missing__\"");
    }

    @Test
    public void termsAggregationWithMissingOnNumber() {
        assertTermsAggregationWithMissing("rank", "-1");
    }

    private void assertTermsAggregationWithMissing(String field, String missing) {
        try (TestRestClient client = cluster.getRestClient(user)) {
            var response = client.postJson(
                INDEX + "/_search",
                "{\"size\":0,\"aggs\":{\"values\":{\"terms\":{\"field\":\"" + field + "\",\"missing\":" + missing + "}}}}"
            );
            response.assertStatusCode(200);
            int docCount = 0;
            for (JsonNode bucket : response.bodyAsJsonNode().at("/aggregations/values/buckets")) {
                docCount += bucket.get("doc_count").asInt();
            }
            // Every document is counted once, either under its own value or under the missing value.
            assertEquals(DOCS.size(), docCount);
        }
    }

    private void assertHits(JsonNode body, int distanceSortIndex, double metersPerUnit, List<String> expectedIds) {
        assertEquals(DOCS.size(), body.at("/hits/total/value").asInt());
        List<String> ids = new ArrayList<>();
        for (JsonNode hit : body.at("/hits/hits")) {
            String id = hit.get("_id").asText();
            ids.add(id);
            double expectedDistance = distanceMeters(latitudeOf(id)) / metersPerUnit;
            assertEquals(id, expectedDistance, hit.at("/sort/" + distanceSortIndex).asDouble(), expectedDistance * 1e-3 + 1e-3);
            assertSource(id, hit.get("_source"));
        }
        assertEquals(expectedIds, ids);
    }

    private void assertSource(String id, JsonNode source) {
        assertTrue(id, source.has("location"));
        boolean statusVisible = user != FLS_EXCLUDE_AND_MASKED && user != FLS_INCLUDE_AND_MASKED;
        assertEquals(id, statusVisible, source.has("status"));
        String owner = ownerOf(id);
        if (user == ALL_ACCESS || user == PLAIN) {
            assertEquals(id, owner, source.get("owner").asText());
        } else {
            String rule = user == MASKED_WILDCARD ? "own*" : "owner";
            String masked = new MaskedField(
                rule,
                Salt.from(Settings.builder().put("plugins.security.compliance.salt", SALT).build()),
                "SHA-256"
            ).mask(owner);
            assertFalse(id, owner.equals(source.get("owner").asText()));
            assertEquals(id, masked, source.get("owner").asText());
        }
    }

    private static String geoSort(String unit) {
        return geoSort(originPoint(), unit + "\"order\":\"asc\"");
    }

    private static String geoSort(String points, String options) {
        return "{\"_geo_distance\":{\"location\":" + points + "," + options + "}}";
    }

    private static String originPoint() {
        return "{\"lat\":" + ORIGIN_LAT + ",\"lon\":" + ORIGIN_LON + "}";
    }

    // All documents share the origin's longitude, so the arc distance is the latitude difference along a meridian.
    private static double distanceMeters(double lat) {
        return Math.toRadians(Math.abs(lat - ORIGIN_LAT)) * EARTH_MEAN_RADIUS_METERS;
    }

    private static double latitudeOf(String id) {
        return (double) DOCS.stream().filter(doc -> doc[0].equals(id)).findFirst().orElseThrow()[1];
    }

    private static String ownerOf(String id) {
        return (String) DOCS.stream().filter(doc -> doc[0].equals(id)).findFirst().orElseThrow()[2];
    }
}
