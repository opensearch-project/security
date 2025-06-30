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
import org.opensearch.protobufs.SearchRequest;
import org.opensearch.protobufs.SearchRequestBody;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestGrpcClient;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.plugin.transport.grpc.ssl.SecureNetty4GrpcServerTransport.GRPC_SECURE_TRANSPORT_SETTING_KEY;
import static org.opensearch.plugin.transport.grpc.ssl.SecureNetty4GrpcServerTransport.SETTING_GRPC_SECURE_PORT;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_CLIENTAUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.transport.AuxTransport.AUX_TRANSPORT_TYPES_KEY;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GrpcTests {
    private static final TestCertificates TEST_CERTIFICATES = new TestCertificates();
    private static final Map<String, Object> SECURE_GRPC_TRANSPORT_SETTINGS = Map.of(
            ConfigConstants.SECURITY_SSL_ONLY, true,
            AUX_TRANSPORT_TYPES_KEY, GRPC_SECURE_TRANSPORT_SETTING_KEY,
            SETTING_GRPC_SECURE_PORT.getKey(), "9400-9500",
            SECURITY_SSL_AUX_ENABLED.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), true,
            SECURITY_SSL_AUX_PEMKEY_FILEPATH.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), TEST_CERTIFICATES.getNodeKey(0, null).getAbsolutePath(),
            SECURITY_SSL_AUX_PEMCERT_FILEPATH.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), TEST_CERTIFICATES.getNodeCertificate(0).getAbsolutePath(),
            SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), TEST_CERTIFICATES.getRootCertificate().getAbsolutePath()
    );
    private static final Map<String, Object> CLIENT_AUTH_NONE = Map.of(SECURITY_SSL_AUX_CLIENTAUTH_MODE.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), ClientAuth.NONE.name());
    private static final Map<String, Object> CLIENT_AUTH_OPT = Map.of(SECURITY_SSL_AUX_CLIENTAUTH_MODE.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), ClientAuth.OPTIONAL.name());
    private static final Map<String, Object> CLIENT_AUTH_REQUIRE = Map.of(SECURITY_SSL_AUX_CLIENTAUTH_MODE.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(), ClientAuth.REQUIRE.name());

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .plugin(GrpcPlugin.class)
            .certificates(TEST_CERTIFICATES)
            .nodeSettings(SECURE_GRPC_TRANSPORT_SETTINGS)
            .nodeSettings(CLIENT_AUTH_OPT)
            .loadConfigurationIntoIndex(false)
            .sslOnly(true)
            .build();


    @Test
    public void testSearch() {
        try (TestRestClient client = cluster.getRestClient()) {
            TestRestClient.HttpResponse response = client.put("test-index");
            response.assertStatusCode(200);
            client.postJson("test-index/_doc/1", "{\"field\": \"value\"}");
        }

        TestGrpcClient client = cluster.getGrpcClient(TEST_CERTIFICATES);

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
