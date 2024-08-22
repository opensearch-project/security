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

import java.nio.CharBuffer;

import com.carrotsearch.randomizedtesting.RandomizedTest;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import com.password4j.BcryptFunction;
import com.password4j.CompressedPBKDF2Function;
import com.password4j.Password;
import com.password4j.types.Bcrypt;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class HashingTests extends RandomizedTest {

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    static final String PASSWORD = "top$ecret1234!";

    public void createUserWithPlainTextPassword(LocalCluster cluster, String username, String password) {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse httpResponse = client.putJson(
                "_plugins/_security/api/internalusers/" + username,
                String.format("{\"password\": \"%s\",\"opendistro_security_roles\": []}", password)
            );
            assertThat(httpResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        }
    }

    public void createUserWithHashedPassword(LocalCluster cluster, String username, String hashedPassword) {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse httpResponse = client.putJson(
                "_plugins/_security/api/internalusers/" + username,
                String.format("{\"hash\": \"%s\",\"opendistro_security_roles\": []}", hashedPassword)
            );
            assertThat(httpResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        }
    }

    public void testPasswordAuth(LocalCluster cluster, String username, String password, int expectedStatusCode) {
        try (TestRestClient client = cluster.getRestClient(username, password)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();
            response.assertStatusCode(expectedStatusCode);
        }
    }

    public static String generateBCryptHash(String password, String minor, int rounds) {
        return Password.hash(CharBuffer.wrap(password.toCharArray()))
            .with(BcryptFunction.getInstance(Bcrypt.valueOf(minor), rounds))
            .getResult();
    }

    public static String generatePBKDF2Hash(String password, String algorithm, int iterations, int length) {
        return Password.hash(CharBuffer.wrap(password.toCharArray()))
            .with(CompressedPBKDF2Function.getInstance(algorithm, iterations, length))
            .getResult();
    }

}
