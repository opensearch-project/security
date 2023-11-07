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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

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
            .build();
    }
}
