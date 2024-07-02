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

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.junit.ClassRule;
import org.junit.Test;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.apache.http.HttpStatus.*;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR_DEFAULT;
import static org.opensearch.security.support.ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS_DEFAULT;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

public class BCryptDefaultConfigHashingTests extends HashingTests {

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .anonymousAuth(false)
        .nodeSettings(Map.of(SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName())))
        .build();

    @Test
    public void shouldAuthenticateWhenUserCreatedWithLegacyHash() {
        String hash = generateLegacyBCryptHash(PASSWORD.toCharArray());
        createUserWithHashedPassword(cluster, "user_1", hash);
        testPasswordAuth(cluster, "user_1", PASSWORD, SC_OK);
    }

    @Test
    public void shouldAuthenticateWithCorrectPassword() {
        String hash = generateBCryptHash(
            PASSWORD,
            SECURITY_PASSWORD_HASHING_BCRYPT_MINOR_DEFAULT,
            SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS_DEFAULT
        );
        createUserWithHashedPassword(cluster, "user_2", hash);
        testPasswordAuth(cluster, "user_2", PASSWORD, SC_OK);

        createUserWithPlainTextPassword(cluster, "user_3", PASSWORD);
        testPasswordAuth(cluster, "user_3", PASSWORD, SC_OK);
    }

    @Test
    public void shouldNotAuthenticateWithIncorrectPassword() {
        String hash = generateBCryptHash(
            PASSWORD,
            SECURITY_PASSWORD_HASHING_BCRYPT_MINOR_DEFAULT,
            SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS_DEFAULT
        );
        createUserWithHashedPassword(cluster, "user_4", hash);
        testPasswordAuth(cluster, "user_4", "wrong_password", SC_UNAUTHORIZED);

        createUserWithPlainTextPassword(cluster, "user_5", PASSWORD);
        testPasswordAuth(cluster, "user_5", "wrong_password", SC_UNAUTHORIZED);
    }

    private String generateLegacyBCryptHash(final char[] clearTextPassword) {
        final byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        final String hash = OpenBSDBCrypt.generate((Objects.requireNonNull(clearTextPassword)), salt, 12);
        Arrays.fill(salt, (byte) 0);
        Arrays.fill(clearTextPassword, '\0');
        return hash;
    }
}
