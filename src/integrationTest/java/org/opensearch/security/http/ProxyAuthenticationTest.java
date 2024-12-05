/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.http;

import java.io.IOException;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AuthenticationBackend;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.HttpAuthenticator;
import org.opensearch.test.framework.XffConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
* Class used to run tests defined in the supper class against OpenSearch cluster with configured <code>proxy</code> authentication.
*/
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ProxyAuthenticationTest extends CommonProxyAuthenticationTests {

    private static final Map<String, Object> PROXY_AUTHENTICATOR_CONFIG = Map.of(
        "user_header",
        HEADER_PROXY_USER,
        "roles_header",
        HEADER_PROXY_ROLES
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .xff(new XffConfig(true).internalProxiesRegexp("127\\.0\\.0\\.10"))
        .authc(
            new AuthcDomain("proxy_auth_domain", -5, true).httpAuthenticator(
                new HttpAuthenticator("proxy").challenge(false).config(PROXY_AUTHENTICATOR_CONFIG)
            ).backend(new AuthenticationBackend("noop"))
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .roles(ROLE_ALL_INDEX_SEARCH, ROLE_PERSONAL_INDEX_SEARCH)
        .rolesMapping(ROLES_MAPPING_CAPTAIN, ROLES_MAPPING_FIRST_MATE)
        .build();

    @Override
    protected LocalCluster getCluster() {
        return cluster;
    }

    @Test
    @Override
    public void shouldAuthenticateWithBasicAuthWhenProxyAuthenticationIsConfigured() {
        super.shouldAuthenticateWithBasicAuthWhenProxyAuthenticationIsConfigured();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_positiveUserKirk() throws IOException {
        super.shouldAuthenticateWithProxy_positiveUserKirk();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_positiveUserSpock() throws IOException {
        super.shouldAuthenticateWithProxy_positiveUserSpock();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_negativeWhenXffHeaderIsMissing() throws IOException {
        super.shouldAuthenticateWithProxy_negativeWhenXffHeaderIsMissing();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_negativeWhenUserNameHeaderIsMissing() throws IOException {
        super.shouldAuthenticateWithProxy_negativeWhenUserNameHeaderIsMissing();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxyWhenRolesHeaderIsMissing() throws IOException {
        super.shouldAuthenticateWithProxyWhenRolesHeaderIsMissing();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_negativeWhenRequestWasNotSendByProxy() throws IOException {
        super.shouldAuthenticateWithProxy_negativeWhenRequestWasNotSendByProxy();
    }

    @Test
    @Override
    public void shouldRetrieveEmptyListOfRoles() throws IOException {
        super.shouldRetrieveEmptyListOfRoles();
    }

    @Test
    @Override
    public void shouldRetrieveSingleRoleFirstMate() throws IOException {
        super.shouldRetrieveSingleRoleFirstMate();
    }

    @Test
    @Override
    public void shouldRetrieveSingleRoleCaptain() throws IOException {
        super.shouldRetrieveSingleRoleCaptain();
    }

    @Test
    @Override
    public void shouldRetrieveMultipleRoles() throws IOException {
        super.shouldRetrieveMultipleRoles();
    }
}
