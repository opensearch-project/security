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

package org.opensearch.test;

import org.junit.runner.RunWith;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AbstractIntegrationTest {

	/**
	 * Auth domain with HTTPS Basic and the internal user backend
	 */
	protected final static TestSecurityConfig.AuthcDomain AUTHC_HTTPBASIC_INTERNAL = new TestSecurityConfig.AuthcDomain("basic", 0)
			.httpAuthenticator("basic").backend("internal");

	/**
	 * Admin user with full access to all indices
	 */
	protected final static TestSecurityConfig.User USER_ADMIN = new TestSecurityConfig.User("admin")
			.roles(new Role("allaccess").indexPermissions("*").on("*").clusterPermissions("*"));

}
