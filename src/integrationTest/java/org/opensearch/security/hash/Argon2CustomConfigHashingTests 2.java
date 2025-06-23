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

import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import static org.hamcrest.Matchers.equalTo;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

public class Argon2CustomConfigHashingTests extends HashingTests {

    public static LocalCluster cluster;

    private static final String PASSWORD = "top$ecret1234!";

    private static String type;
    private static int memory, iterations, parallelism, length, version;

    @BeforeClass
    public static void startCluster() {

        type = randomFrom(List.of("argon2id", "argon2i", "argon2d"));
        iterations = randomFrom(List.of(2, 3, 4));
        memory = randomFrom(List.of(65536, 131072));
        parallelism = randomFrom(List.of(1, 2));
        length = randomFrom(List.of(16, 32, 64));
        version = randomFrom(List.of(16, 19));

        TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS)
            .hash(generateArgon2Hash("secret", memory, iterations, parallelism, length, type, version));
        cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(ADMIN_USER)
            .anonymousAuth(false)
            .nodeSettings(
                Map.of(
                    ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED,
                    List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                    ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM,
                    ConfigConstants.ARGON2,
                    ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_MEMORY,
                    memory,
                    ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS,
                    iterations,
                    ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM,
                    parallelism,
                    ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_LENGTH,
                    length,
                    ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_TYPE,
                    type,
                    ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_VERSION,
                    version
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
        String hash = generateArgon2Hash(PASSWORD, memory, iterations, parallelism, length, type, version);
        createUserWithHashedPassword(cluster, "user_1", hash);
        testPasswordAuth(cluster, "user_1", PASSWORD, HttpStatus.SC_OK);

        createUserWithPlainTextPassword(cluster, "user_2", PASSWORD);
        testPasswordAuth(cluster, "user_2", PASSWORD, HttpStatus.SC_OK);
    }

    @Test
    public void shouldNotAuthenticateWithIncorrectPassword() {
        String hash = generateArgon2Hash(PASSWORD, memory, iterations, parallelism, length, type, version);
        createUserWithHashedPassword(cluster, "user_3", hash);
        testPasswordAuth(cluster, "user_3", "wrong_password", HttpStatus.SC_UNAUTHORIZED);

        createUserWithPlainTextPassword(cluster, "user_4", PASSWORD);
        testPasswordAuth(cluster, "user_4", "wrong_password", HttpStatus.SC_UNAUTHORIZED);
    }
}