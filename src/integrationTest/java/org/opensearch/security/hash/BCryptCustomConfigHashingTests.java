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
public class BCryptCustomConfigHashingTests extends HashingTests {

    private LocalCluster cluster;

    private final String minor;

    private final int rounds;

    public BCryptCustomConfigHashingTests(String minor, int rounds) {
        this.minor = minor;
        this.rounds = rounds;
    }

    @Parameterized.Parameters(name = "minor={0}, rounds={1}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] { { "A", 4 }, { "B", 6 }, { "Y", 10 }, { "A", 10 }, { "B", 4 }, { "Y", 6 } });
    }

    @Before
    public void startCluster() {
        TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS)
            .hash(generateBCryptHash("secret", minor, rounds));
        cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(ADMIN_USER)
            .anonymousAuth(false)
            .nodeSettings(
                Map.of(
                    ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED,
                    List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                    ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM,
                    ConfigConstants.BCRYPT,
                    ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR,
                    minor,
                    ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS,
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

    @After
    public void stopCluster() {
        if (cluster != null) {
            cluster.close();
        }
    }

    @Test
    public void shouldAuthenticateWithCorrectPassword() {
        String hash = generateBCryptHash(PASSWORD, minor, rounds);
        createUserWithHashedPassword(cluster, "user_2", hash);
        testPasswordAuth(cluster, "user_2", PASSWORD, HttpStatus.SC_OK);

        createUserWithPlainTextPassword(cluster, "user_3", PASSWORD);
        testPasswordAuth(cluster, "user_3", PASSWORD, HttpStatus.SC_OK);
    }

    @Test
    public void shouldNotAuthenticateWithIncorrectPassword() {
        String hash = generateBCryptHash(PASSWORD, minor, rounds);
        createUserWithHashedPassword(cluster, "user_4", hash);
        testPasswordAuth(cluster, "user_4", "wrong_password", HttpStatus.SC_UNAUTHORIZED);

        createUserWithPlainTextPassword(cluster, "user_5", PASSWORD);
        testPasswordAuth(cluster, "user_5", "wrong_password", HttpStatus.SC_UNAUTHORIZED);
    }
}
