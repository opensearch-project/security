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
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

public class PBKDF2DefaultConfigHashingTests extends HashingTests {

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS)
        .hash(
            generatePBKDF2Hash(
                "secret",
                ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION_DEFAULT,
                ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS_DEFAULT,
                ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH_DEFAULT
            )
        );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM,
                ConfigConstants.PBKDF2
            )
        )
        .build();

    @Test
    public void shouldAuthenticateWithCorrectPassword() {
        String hash = generatePBKDF2Hash(
            PASSWORD,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH_DEFAULT
        );
        createUserWithHashedPassword(cluster, "user_1", hash);
        testPasswordAuth(cluster, "user_1", PASSWORD, HttpStatus.SC_OK);

        createUserWithPlainTextPassword(cluster, "user_2", PASSWORD);
        testPasswordAuth(cluster, "user_2", PASSWORD, HttpStatus.SC_OK);
    }

    @Test
    public void shouldNotAuthenticateWithIncorrectPassword() {
        String hash = generatePBKDF2Hash(
            PASSWORD,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH_DEFAULT
        );
        createUserWithHashedPassword(cluster, "user_3", hash);
        testPasswordAuth(cluster, "user_3", "wrong_password", HttpStatus.SC_UNAUTHORIZED);

        createUserWithPlainTextPassword(cluster, "user_4", PASSWORD);
        testPasswordAuth(cluster, "user_4", "wrong_password", HttpStatus.SC_UNAUTHORIZED);
    }
}
