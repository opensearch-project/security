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

package org.opensearch.security.privileges;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.user.User;

import java.util.List;
import java.util.Set;

import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT;

public class PrivilegesEvaluatorTest extends SingleClusterTest {
    private static final Header NegativeLookaheadUserHeader = encodeBasicHeader("negative_lookahead_user", "negative_lookahead_user");
    private static final Header NegatedRegexUserHeader = encodeBasicHeader("negated_regex_user", "negated_regex_user");

    public void setupSettingsIndexPattern() throws Exception {
        Settings settings = Settings.builder().build();
        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setSecurityRoles("roles_index_patterns.yml")
                .setSecurityInternalUsers("internal_users_index_patterns.yml")
                .setSecurityRolesMapping("roles_mapping_index_patterns.yml"),
            settings,
            true
        );
    }

    @Test
    public void testNegativeLookaheadPattern() throws Exception {
        setupSettingsIndexPattern();

        RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse response = rh.executeGetRequest("*/_search", NegativeLookaheadUserHeader);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        response = rh.executeGetRequest("r*/_search", NegativeLookaheadUserHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testRegexPattern() throws Exception {
        setupSettingsIndexPattern();

        RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse response = rh.executeGetRequest("*/_search", NegatedRegexUserHeader);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        response = rh.executeGetRequest("r*/_search", NegatedRegexUserHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testSetUserInfoInThreadContext() throws Exception {

        User userA = new User("userA");
        userA.setAuthDomain("basic_internal_auth_domain");
        userA.setInternal(true);
        userA.addRoles(List.of("backendRole1", "backendRole2"));
        userA.addSecurityRoles(List.of("role1"));
        userA.setRequestedTenant("customTenant");

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        PrivilegesEvaluator.setUserInfoInThreadContext(threadContext, userA, Set.of("mappedRole1", "mappedRole2"));

        Assert.assertEquals(
            "userA|backendRole2,backendRole1|role1,mappedRole2,mappedRole1|customTenant|true|basic_internal_auth_domain",
            threadContext.getTransient(OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT)
        );
    }
}
