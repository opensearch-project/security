/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.api;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.SecurityConfigurationTests.ADDITIONAL_USER_1;
import static org.opensearch.security.SecurityConfigurationTests.CREATE_USER_BODY;
import static org.opensearch.security.SecurityConfigurationTests.INTERNAL_USERS_RESOURCE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class CreateResetPasswordTest {

    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

    public static final String INVALID_PASSWORD_REGEX = "user 1 fair password";

    public static final String VALID_WEAK_PASSWORD = "Asdfghjkl1!";

    public static final String VALID_SIMILAR_PASSWORD = "456Additional00001_1234!";

    private static final String CUSTOM_PASSWORD_MESSAGE =
        "Password must be minimum 5 characters long and must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.";

    private static final String CUSTOM_PASSWORD_REGEX = "(?=.*[A-Z])(?=.*[^a-zA-Z\\d])(?=.*[0-9])(?=.*[a-z]).{5,}";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST,
                false,
                ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX,
                CUSTOM_PASSWORD_REGEX,
                ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE,
                CUSTOM_PASSWORD_MESSAGE
            )
        )
        .build();

    @Test
    public void shouldValidateCreateUserAPIErrorMessages() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse httpResponse = client.putJson(
                INTERNAL_USERS_RESOURCE + ADDITIONAL_USER_1,
                String.format(CREATE_USER_BODY, INVALID_PASSWORD_REGEX)
            );

            assertThat(httpResponse.getStatusCode(), equalTo(400));
            assertThat(httpResponse.getBody(), containsString(CUSTOM_PASSWORD_MESSAGE));
        }

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse httpResponse = client.putJson(
                INTERNAL_USERS_RESOURCE + ADDITIONAL_USER_1,
                String.format(CREATE_USER_BODY, VALID_WEAK_PASSWORD)
            );

            assertThat(httpResponse.getStatusCode(), equalTo(400));
            assertThat(httpResponse.getBody(), containsString(RequestContentValidator.ValidationError.WEAK_PASSWORD.message()));
        }

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse httpResponse = client.putJson(
                INTERNAL_USERS_RESOURCE + ADDITIONAL_USER_1,
                String.format(CREATE_USER_BODY, VALID_SIMILAR_PASSWORD)
            );

            assertThat(httpResponse.getStatusCode(), equalTo(400));
            assertThat(httpResponse.getBody(), containsString(RequestContentValidator.ValidationError.SIMILAR_PASSWORD.message()));
        }
    }

}
