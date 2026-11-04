/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.privileges.int_tests;

import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.privileges.int_tests.PluginSystemIndexRealtimeIntTests.INDEX_WITHOUT_REFRESH;
import static org.opensearch.security.privileges.int_tests.PluginSystemIndexRealtimeIntTests.assertAdminReadsUnrefreshedDocument;
import static org.opensearch.security.privileges.int_tests.PluginSystemIndexRealtimeIntTests.startReadingUnrefreshedDocumentsFromTranslog;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PROTECTED_INDICES_ENABLED_KEY;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PROTECTED_INDICES_KEY;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PROTECTED_INDICES_ROLES_KEY;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1.SYSTEM_INDEX_1;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * When a plugin's own system index is also a protected index, the security index searcher wrapper hides it from the
 * plugin subject, which has no protected index role. The legacy evaluator then keeps the plugin's reads non-realtime,
 * so a realtime read from the translog does not show what the wrapper hides.
 */
public class PluginProtectedSystemIndexRealtimeIntTests {

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().singleNode()
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .plugin(SystemIndexPlugin1.class)
        .doNotFailOnForbidden(true)
        .nodeSettings(
            Map.of(
                SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                true,
                SECURITY_PROTECTED_INDICES_ENABLED_KEY,
                true,
                SECURITY_PROTECTED_INDICES_KEY,
                List.of(SYSTEM_INDEX_1),
                SECURITY_PROTECTED_INDICES_ROLES_KEY,
                List.of("protected_index_role")
            )
        )
        .build();

    @Test
    public void pluginSubjectGetOnItsOwnProtectedIndexStaysNonRealtime() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            assertThat(client.putJson(SYSTEM_INDEX_1, INDEX_WITHOUT_REFRESH), isOk());
        }
        startReadingUnrefreshedDocumentsFromTranslog(cluster, SYSTEM_INDEX_1);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("write-then-read-on-system-index/" + SYSTEM_INDEX_1 + "/doc1");

            assertThat(response, isOk());
            assertThat(response.getBooleanFromJsonBody("/found"), equalTo(false));
        }
        assertAdminReadsUnrefreshedDocument(cluster, SYSTEM_INDEX_1, "doc1");
    }
}
