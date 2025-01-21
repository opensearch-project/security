/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.systemindex;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.runner.RunWith;

import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1;
import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SystemIndexTests extends AbstractSystemIndexTests {

    public static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0).httpAuthenticatorWithChallenge("basic").backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_DOMAIN)
        .users(USER_ADMIN)
        .plugin(SystemIndexPlugin1.class, SystemIndexPlugin2.class)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                true
            )
        )
        .build();

    public SystemIndexTests() {
        super(cluster);
    }
}
