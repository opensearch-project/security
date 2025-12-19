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

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(Parameterized.class)
public class Argon2CustomConfigHashingTests extends HashingTests {

    public LocalCluster cluster;

    private static final String PASSWORD = "top$ecret1234!";

    private final String type;
    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final int length;
    private final int version;

    public Argon2CustomConfigHashingTests(String type, int memory, int iterations, int parallelism, int length, int version) {
        this.type = type;
        this.memory = memory;
        this.iterations = iterations;
        this.parallelism = parallelism;
        this.length = length;
        this.version = version;
    }

    @Parameterized.Parameters(name = "type={0}, memory={1}, iterations={2}, parallelism={3}, length={4}, version={5}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
            { "argon2id", 65536, 2, 1, 16, 19 },
            { "argon2id", 131072, 3, 2, 32, 16 },
            { "argon2i", 65536, 2, 1, 16, 19 },
            { "argon2i", 131072, 3, 2, 32, 16 },
            { "argon2d", 65536, 2, 1, 16, 19 },
            { "argon2d", 131072, 3, 2, 32, 16 }
        });
    }

    @Before
    public void startCluster() {

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

    @After
    public void stopCluster() {
        if (cluster != null) {
            cluster.close();
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
