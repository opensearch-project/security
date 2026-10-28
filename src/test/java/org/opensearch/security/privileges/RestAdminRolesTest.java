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

import java.util.List;
import java.util.Set;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class RestAdminRolesTest {

    private final RestAdminRoles restAdminRoles = new RestAdminRoles(
        Settings.builder()
            .putList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of("all_access", "security_rest_api_access"))
            .build()
    );

    private final RestAdminRoles unconfigured = new RestAdminRoles(Settings.EMPTY);

    @Test
    public void matches_trueWhenAnyMappedRoleIsConfigured() {
        assertThat(restAdminRoles.matches(Set.of("all_access")), is(true));
        assertThat(restAdminRoles.matches(Set.of("readall", "security_rest_api_access")), is(true));
    }

    @Test
    public void matches_falseForOtherRolesEmptyOrNull() {
        assertThat(restAdminRoles.matches(Set.of("readall")), is(false));
        assertThat(restAdminRoles.matches(Set.of()), is(false));
        assertThat(restAdminRoles.matches(null), is(false));
    }

    @Test
    public void matches_isExactNotWildcard() {
        RestAdminRoles wildcardEntry = new RestAdminRoles(
            Settings.builder().putList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of("sec_*")).build()
        );
        assertThat(wildcardEntry.matches(Set.of("sec_admin")), is(false));
        assertThat(wildcardEntry.matches(Set.of("sec_*")), is(true));
    }

    @Test
    public void matches_falseWhenNothingConfigured() {
        assertThat(unconfigured.matches(Set.of("all_access")), is(false));
    }

    @Test
    public void isEmptyAndRoles_reflectConfiguration() {
        assertThat(restAdminRoles.isEmpty(), is(false));
        assertThat(restAdminRoles.roles(), equalTo(Set.of("all_access", "security_rest_api_access")));
        assertThat(unconfigured.isEmpty(), is(true));
        assertThat(unconfigured.roles(), equalTo(Set.of()));
    }
}
