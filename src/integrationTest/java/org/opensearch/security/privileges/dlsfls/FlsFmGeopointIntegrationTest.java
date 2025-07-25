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
package org.opensearch.security.privileges.dlsfls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.plugin.mapper.MapperSizePlugin;
import org.opensearch.security.privileges.dlsfls.FlsFmIntegrationTests.FieldNamePredicate;
import org.opensearch.test.framework.TestData;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.collect.ImmutableMap;

/**
 * This test applies FLS and field masking to a index with a geopoint field and makes sures to
 * handle the null pointer exception specified in the pull request
 *  <a href="https://github.com/opensearch-project/security/pull/5504">#5504</a>
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class FlsFmGeopointIntegrationTest {

    static final String FIELD_MASKING_SALT = "mytestsaresalted";
    static final String GEOPOINT_INDEX = "geopoint_index";

    static final TestSecurityConfig.User.MetadataKey<TestData.DocumentTransformer> DOC_WITH_FLS_FM_APPLIED =
        new TestSecurityConfig.User.MetadataKey<>("doc_with_fls_fm_applied", TestData.DocumentTransformer.class);

    /**
     * A predicate assigned to a user that determines whether a field can be searched by this user.
     * Fields protected by FLS and field masking cannot be searched.
     */
    static final TestSecurityConfig.User.MetadataKey<FieldNamePredicate> FIELD_IS_SEARCHABLE = new TestSecurityConfig.User.MetadataKey<>(
        "field_is_searchable",
        FieldNamePredicate.class
    );

    /**
     * A predicate assigned to a user that determines whether a field can be searched by this user.
     * Fields protected by FLS cannot be aggregated. However, fields protected by field masking can be aggregated.
     */
    static final TestSecurityConfig.User.MetadataKey<FieldNamePredicate> FIELD_IS_AGGREGABLE = new TestSecurityConfig.User.MetadataKey<>(
        "field_is_aggregable",
        FieldNamePredicate.class
    );

    static TestSecurityConfig.User FULL = new TestSecurityConfig.User("full").description("May see everything")
        .roles(
            new TestSecurityConfig.Role("all_access").clusterPermissions("*").indexPermissions("*").on("*")
        )
        .reference(DOC_WITH_FLS_FM_APPLIED, doc -> doc)
        .reference(FIELD_IS_SEARCHABLE, field -> true)
        .reference(FIELD_IS_AGGREGABLE, field -> true);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .plugin(MapperSizePlugin.class)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(FULL)
        .nodeSettings(ImmutableMap.of("plugins.security.compliance.salt", FIELD_MASKING_SALT))
        .build();

    @Test
    public void search_sortBy_geopoint_field() {
        String mapping = """
            {
    "mappings": {
        "properties": {
            "admin1": {
                "type": "keyword"
            },
            "admin2": {
                "type": "keyword"
            },
            "admin3": {
                "type": "keyword"
            },
            "admin4": {
                "type": "keyword"
            },
            "coordinates": {
                "type": "geo_point"
            },
            "countryCode": {
                "type": "keyword"
            },
            "elevation": {
                "type": "long",
                "index": false
            },
            "featureClass": {
                "type": "keyword"
            },
            "featureCode": {
                "type": "keyword"
            },
            "id": {
                "type": "long"
            },
            "population": {
                "type": "long"
            },
            "timezone": {
                "type": "text",
                "index": false
            }
        }
    }
}""";

        String document = """
            {
    "admin1": "11",
    "admin2": "75",
    "admin3": "751",
    "admin4": "75056",
    "coordinates": {
        "lat": 48.8331,
        "lon": 2.3264
    },
    "countryCode" : "FR",
    "elevation" : 0,
    "featureClass" : "A",
    "featureCode" : "ADM5",
    "id" : 6618620,
    "population" : 137105,
    "timezone" : "Europe/Paris"
}""";  
      
        TestRestClient client = cluster.getRestClient(FULL);
        TestRestClient.HttpResponse response = client.putJson(GEOPOINT_INDEX, mapping);
        assertThat(response, isOk());
        response = client.postJson(GEOPOINT_INDEX + "/_doc/1", document);
        assertEquals(201, response.getStatusCode());

        response = client.postJson(GEOPOINT_INDEX + "/_search", """
            {
                "query": {
                    "bool": {
                        "filter": {
                            "exists": {
                                "field": "coordinates"
                            }
                        }
                    }
                },
                "sort": [
                    {
                        "_geo_distance": {
                            "coordinates": {
                                "lat": 40.7128,
                                "lon": -74.0060
                            },
                            "ignore_unmapped": true,
                            "order": "desc",
                            "unit": "km"
                        }
                    }
                ],
                "size": 4
            }""");
        assertThat(response, isOk());
    }

    TestSecurityConfig.User user;

    public FlsFmGeopointIntegrationTest() {
        this.user = FULL;
    }

}
