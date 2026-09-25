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

import org.opensearch.common.settings.Settings;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

public class Argon2DefaultConfigHashingTests extends HashingTests {

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS)
        .hash(
            generateArgon2Hash(
                "secret",
                PasswordHasherFactory.ARGON2_MEMORY.getDefault(Settings.EMPTY),
                PasswordHasherFactory.ARGON2_ITERATIONS.getDefault(Settings.EMPTY),
                PasswordHasherFactory.ARGON2_PARALLELISM.getDefault(Settings.EMPTY),
                PasswordHasherFactory.ARGON2_LENGTH.getDefault(Settings.EMPTY),
                PasswordHasherFactory.ARGON2_TYPE.getDefault(Settings.EMPTY),
                PasswordHasherFactory.ARGON2_VERSION.getDefault(Settings.EMPTY)
            )
        );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                PasswordHasherFactory.ALGORITHM.getKey(),
                PasswordHasherFactory.ARGON2
            )
        )
        .build();

    @Test
    public void shouldAuthenticateWithCorrectPassword() {
        String hash = generateArgon2Hash(
            PASSWORD,
            PasswordHasherFactory.ARGON2_MEMORY.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_ITERATIONS.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_PARALLELISM.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_LENGTH.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_TYPE.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_VERSION.getDefault(Settings.EMPTY)
        );
        createUserWithHashedPassword(cluster, "user_1", hash);
        testPasswordAuth(cluster, "user_1", PASSWORD, HttpStatus.SC_OK);

        createUserWithPlainTextPassword(cluster, "user_2", PASSWORD);
        testPasswordAuth(cluster, "user_2", PASSWORD, HttpStatus.SC_OK);
    }

    @Test
    public void shouldNotAuthenticateWithIncorrectPassword() {
        String hash = generateArgon2Hash(
            PASSWORD,
            PasswordHasherFactory.ARGON2_MEMORY.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_ITERATIONS.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_PARALLELISM.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_LENGTH.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_TYPE.getDefault(Settings.EMPTY),
            PasswordHasherFactory.ARGON2_VERSION.getDefault(Settings.EMPTY)
        );
        createUserWithHashedPassword(cluster, "user_3", hash);
        testPasswordAuth(cluster, "user_3", "wrongpassword", HttpStatus.SC_UNAUTHORIZED);

        createUserWithPlainTextPassword(cluster, "user_4", PASSWORD);
        testPasswordAuth(cluster, "user_4", "wrongpassword", HttpStatus.SC_UNAUTHORIZED);
    }
}
