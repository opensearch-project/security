/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class IpBruteForceAttacksPreventionWithDomainChallengeTests extends IpBruteForceAttacksPreventionTests {
    @Override
    public LocalCluster createCluster() {
        return new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .anonymousAuth(false)
            .authFailureListeners(listener)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USER_1, USER_2)
            .nodeSettings(
                Map.of(
                    SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION,
                    true,
                    SECURITY_RESTAPI_ROLES_ENABLED,
                    List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                    SECURITY_RESTAPI_ADMIN_ENABLED,
                    true
                )
            )
            .build();
    }
}
