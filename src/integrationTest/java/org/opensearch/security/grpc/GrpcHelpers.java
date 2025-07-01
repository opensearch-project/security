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

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import io.netty.handler.ssl.ClientAuth;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.plugin.transport.grpc.GrpcPlugin;
import org.opensearch.protobufs.MatchAllQuery;
import org.opensearch.protobufs.QueryContainer;
import org.opensearch.protobufs.SearchRequest;
import org.opensearch.protobufs.SearchRequestBody;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestGrpcClient;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.plugin.transport.grpc.ssl.SecureNetty4GrpcServerTransport.GRPC_SECURE_TRANSPORT_SETTING_KEY;
import static org.opensearch.plugin.transport.grpc.ssl.SecureNetty4GrpcServerTransport.SETTING_GRPC_SECURE_PORT;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_CLIENTAUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.transport.AuxTransport.AUX_TRANSPORT_TYPES_KEY;

public class GrpcHelpers {
    protected static final TestCertificates TEST_CERTIFICATES = new TestCertificates();
    protected static final Map<String, Object> CLIENT_AUTH_NONE = Map.of(SECURITY_SSL_AUX_CLIENTAUTH_MODE.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), ClientAuth.NONE.name());
    protected static final Map<String, Object> CLIENT_AUTH_OPT = Map.of(SECURITY_SSL_AUX_CLIENTAUTH_MODE.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), ClientAuth.OPTIONAL.name());
    protected static final Map<String, Object> CLIENT_AUTH_REQUIRE = Map.of(SECURITY_SSL_AUX_CLIENTAUTH_MODE.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), ClientAuth.REQUIRE.name());

    private static final Map<String, Object> SECURE_GRPC_TRANSPORT_SETTINGS = Map.of(
            ConfigConstants.SECURITY_SSL_ONLY, true,
            AUX_TRANSPORT_TYPES_KEY, GRPC_SECURE_TRANSPORT_SETTING_KEY,
            SETTING_GRPC_SECURE_PORT.getKey(), "9400-9500",
            SECURITY_SSL_AUX_ENABLED.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), true,
            SECURITY_SSL_AUX_PEMKEY_FILEPATH.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), TEST_CERTIFICATES.getNodeKey(0, null).getAbsolutePath(),
            SECURITY_SSL_AUX_PEMCERT_FILEPATH.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), TEST_CERTIFICATES.getNodeCertificate(0).getAbsolutePath(),
            SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), TEST_CERTIFICATES.getRootCertificate().getAbsolutePath()
    );

    public static LocalCluster.Builder baseGrpcCluster(){
        return new LocalCluster.Builder()
                .clusterManager(ClusterManager.SINGLENODE)
                .plugin(GrpcPlugin.class)
                .certificates(TEST_CERTIFICATES)
                .nodeSettings(SECURE_GRPC_TRANSPORT_SETTINGS)
                .loadConfigurationIntoIndex(false)
                .sslOnly(true);
    }

    public static void createTestIndex(TestRestClient client, String index, long numDocs) {
        try (client) {
            client.put(index).assertStatusCode(200);
            for (int i = 0; i < numDocs; i++) {
                String docURI = index + "/_doc/" + i;
                String docBody = "{\"field\": \"doc " + i + " body\"}";
                client.postJson(docURI, docBody)
                        .assertStatusCode(201);
            }
        }
    }

    protected static SearchResponse grpcMatchAllQuery(TestGrpcClient client, String index, int size) {
        QueryContainer query = QueryContainer.newBuilder()
                .setMatchAll(MatchAllQuery.newBuilder().build())
                .build();
        SearchRequestBody requestBody = SearchRequestBody.newBuilder()
                .setFrom(0)
                .setSize(size)
                .setQuery(query)
                .build();
        SearchRequest searchRequest = SearchRequest.newBuilder()
                .addIndex(index)
                .setRequestBody(requestBody)
                .build();
        return client.search(searchRequest);
    }
}
