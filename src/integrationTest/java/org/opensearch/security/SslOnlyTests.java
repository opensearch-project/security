/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
* Test related to SSL-only mode of security plugin. In this mode, the security plugin is responsible only for TLS/SSL encryption.
* Therefore, the plugin does not perform authentication and authorization. Moreover, the REST resources (e.g. /_plugins/_security/whoami,
* /_plugins/_security/authinfo, etc.) provided by the plugin are not available.
*/
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SslOnlyTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(Map.of(ConfigConstants.SECURITY_SSL_ONLY, true))
        .sslOnly(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .build();

    @Test
    public void shouldNotLoadSecurityPluginResources() {
        try (TestRestClient client = cluster.getRestClient()) {

            HttpResponse response = client.getAuthInfo();

            // in SSL only mode the security plugin does not register a handler for resource /_plugins/_security/whoami. Therefore error
            // response is returned.
            response.assertStatusCode(400);
        }
    }

    @Test
    public void shouldGetIndicesWithoutAuthentication() {
        try (TestRestClient client = cluster.getRestClient()) {

            // request does not contains credential
            HttpResponse response = client.get("_cat/indices");

            // successful response is returned because the security plugin in SSL only mode
            // does not perform authentication and authorization
            response.assertStatusCode(200);
        }
    }
}
