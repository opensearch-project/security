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

package org.opensearch.security.hash;

import java.util.List;
import java.util.Map;

import org.awaitility.Awaitility;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.apache.http.HttpStatus.*;
import static org.apache.http.HttpStatus.SC_UNAUTHORIZED;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.*;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

public class BCryptCustomConfigHashingTests extends HashingTests {

    private static LocalCluster cluster;

    private static String minor;

    private static int rounds;

    @BeforeClass
    public static void startCluster() {
        minor = randomFrom(List.of("A", "B", "Y"));
        rounds = randomIntBetween(4, 10);

        TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS)
            .hash(generateBCryptHash("secret", minor, rounds));
        cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(ADMIN_USER)
            .anonymousAuth(false)
            .nodeSettings(
                Map.of(
                    SECURITY_RESTAPI_ROLES_ENABLED,
                    List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                    SECURITY_PASSWORD_HASHING_ALGORITHM,
                    BCRYPT,
                    SECURITY_PASSWORD_HASHING_BCRYPT_MINOR,
                    minor,
                    SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS,
                    rounds
                )
            )
            .build();
        cluster.before();

        try (TestRestClient client = cluster.getRestClient(ADMIN_USER.getName(), "secret")) {
            Awaitility.await()
                .alias("Load default configuration")
                .until(() -> client.securityHealth().getTextFromJsonBody("/status"), equalTo("UP"));
        }
    }

    @Test
    public void shouldAuthenticateWithCorrectPassword() {
        String hash = generateBCryptHash(PASSWORD, minor, rounds);
        createUserWithHashedPassword(cluster, "user_2", hash);
        testPasswordAuth(cluster, "user_2", PASSWORD, SC_OK);

        createUserWithPlainTextPassword(cluster, "user_3", PASSWORD);
        testPasswordAuth(cluster, "user_3", PASSWORD, SC_OK);
    }

    @Test
    public void shouldNotAuthenticateWithIncorrectPassword() {
        String hash = generateBCryptHash(PASSWORD, minor, rounds);
        createUserWithHashedPassword(cluster, "user_4", hash);
        testPasswordAuth(cluster, "user_4", "wrong_password", SC_UNAUTHORIZED);

        createUserWithPlainTextPassword(cluster, "user_5", PASSWORD);
        testPasswordAuth(cluster, "user_5", "wrong_password", SC_UNAUTHORIZED);
    }
}
