/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.grpc;

import java.io.IOException;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.plugin.transport.grpc.GrpcPlugin;
import org.opensearch.protobufs.SearchRequest;
import org.opensearch.protobufs.SearchRequestBody;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestGrpcClient;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GrpcTests {

    private static final Logger log = LogManager.getLogger(GrpcTests.class);

    static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    private static final TestCertificates TEST_CERTIFICATES = new TestCertificates();

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .testCertificates(TEST_CERTIFICATES)
        .anonymousAuth(false)
        .plugin(GrpcPlugin.class)
        .grpc(TEST_CERTIFICATES)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .build();

    @Test
    public void testSearch() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.put("test-index");
            client.postJson("test-index/_doc/1", "{\"field\": \"value\"}");
        }

        TestGrpcClient client = cluster.getGrpcClient(ADMIN_USER);
        // Create a search request
        SearchRequestBody requestBody = SearchRequestBody.newBuilder().setFrom(0).setSize(10).build();

        SearchRequest searchRequest = SearchRequest.newBuilder()
            .addIndex("test-index")
            .setRequestBody(requestBody)
            .setQ("field:value")
            .build();
        SearchResponse response = client.search(searchRequest);
        System.out.println("Search Response: " + response);
    }
}
