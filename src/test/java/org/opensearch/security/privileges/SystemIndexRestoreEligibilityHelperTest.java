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
import java.util.Optional;
import java.util.Set;

import org.junit.Test;

import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

public class SystemIndexRestoreEligibilityHelperTest {

    private static final String ALERTING_CONFIG = ".opendistro-alerting-config";
    private static final String REPORTS_DEFINITIONS = ".opendistro-reports-definitions";
    private static final String ALERT_HISTORY = ".opendistro-alerting-alert-history-2026.09.24-1";
    private static final String SECURITY_INDEX = ".opendistro_security";

    private final SystemIndexRestoreEligibilityHelper helper = new SystemIndexRestoreEligibilityHelper(
        Settings.builder()
            .putList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of("all_access", "security_rest_api_access"))
            .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY, List.of(ALERTING_CONFIG, ".opendistro-reports-*"))
            .build()
    );

    private final SystemIndexRestoreEligibilityHelper helperWithDefaults = new SystemIndexRestoreEligibilityHelper(
        Settings.builder().putList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of("all_access")).build()
    );

    private static RestoreSnapshotRequest restore(String... indices) {
        return new RestoreSnapshotRequest("repo", "snap").indices(indices);
    }

    @Test
    public void isSecurityAdmin_trueForRestApiRole() {
        assertThat(helper.isSecurityAdmin(Set.of("all_access")), is(true));
        assertThat(helper.isSecurityAdmin(Set.of("readall", "security_rest_api_access")), is(true));
    }

    @Test
    public void isSecurityAdmin_falseForOtherRolesOrNone() {
        assertThat(helper.isSecurityAdmin(Set.of("readall")), is(false));
        assertThat(helper.isSecurityAdmin(Set.of()), is(false));
        assertThat(helper.isSecurityAdmin(null), is(false));
    }

    @Test
    public void isSecurityAdmin_falseWhenRestApiRolesNotConfigured() {
        SystemIndexRestoreEligibilityHelper unconfigured = new SystemIndexRestoreEligibilityHelper(Settings.EMPTY);
        assertThat(unconfigured.isSecurityAdmin(Set.of("all_access")), is(false));
    }

    @Test
    public void isEligible_matchesConfiguredIndicesAndPatterns() {
        assertThat(helper.isEligible(ALERTING_CONFIG), is(true));
        assertThat(helper.isEligible(REPORTS_DEFINITIONS), is(true));
        assertThat(helper.isEligible(ALERT_HISTORY), is(false));
        assertThat(helper.isEligible(SECURITY_INDEX), is(false));
    }

    @Test
    public void isEligible_nothingByDefault() {
        assertThat(helperWithDefaults.isEligible(ALERTING_CONFIG), is(false));
        assertThat(helperWithDefaults.isEligible(REPORTS_DEFINITIONS), is(false));
    }

    @Test
    public void denialReason_emptyForExplicitAllowlistedIndices() {
        RestoreSnapshotRequest request = restore(ALERTING_CONFIG, REPORTS_DEFINITIONS, "my-data");
        assertThat(helper.denialReason(request, Set.of(ALERTING_CONFIG, REPORTS_DEFINITIONS)), equalTo(Optional.empty()));
        assertThat(helper.isRestorableBySecurityAdmin(request, ALERTING_CONFIG), is(true));
    }

    @Test
    public void denialReason_emptyWhenNoSystemIndices() {
        assertThat(helper.denialReason(restore("my-data"), Set.of()), equalTo(Optional.empty()));
        assertThat(helper.denialReason(restore("my-data"), null), equalTo(Optional.empty()));
    }

    @Test
    public void denialReason_listsNonEligibleAndTheRestorableIndices() {
        Optional<String> reason = helper.denialReason(restore(ALERTING_CONFIG, ALERT_HISTORY), Set.of(ALERTING_CONFIG, ALERT_HISTORY));
        assertThat(reason.isPresent(), is(true));
        assertThat(reason.get(), containsString("[" + ALERT_HISTORY + "] are not eligible for restore."));
        assertThat(reason.get(), containsString("Restorable system indices: [" + ALERTING_CONFIG + ", .opendistro-reports-*]."));
    }

    @Test
    public void denialReason_omitsRestorableIndicesWhenNoneConfigured() {
        Optional<String> reason = helperWithDefaults.denialReason(restore(ALERTING_CONFIG), Set.of(ALERTING_CONFIG));
        assertThat(
            reason.get(),
            equalTo("System index restore denied: System indices [" + ALERTING_CONFIG + "] are not eligible for restore.")
        );
        assertThat(reason.get(), not(containsString("Restorable system indices")));
    }

    @Test
    public void denialReason_securityIndexNotEligibleUnlessConfigured() {
        Optional<String> reason = helper.denialReason(restore(SECURITY_INDEX), Set.of(SECURITY_INDEX));
        assertThat(reason.get(), containsString("[" + SECURITY_INDEX + "] are not eligible for restore"));
    }

    @Test
    public void denialReason_wildcardMatchIsNotExplicit() {
        Optional<String> reason = helper.denialReason(restore(".opendistro-alerting-*"), Set.of(ALERTING_CONFIG));
        assertThat(reason.get(), containsString("must be named explicitly"));
        assertThat(helper.isRestorableBySecurityAdmin(restore("*"), ALERTING_CONFIG), is(false));
    }

    @Test
    public void denialReason_nullIndicesIsNotExplicit() {
        RestoreSnapshotRequest request = new RestoreSnapshotRequest("repo", "snap");
        request.indices((String[]) null);
        assertThat(helper.denialReason(request, Set.of(ALERTING_CONFIG)).get(), containsString("must be named explicitly"));
    }

    @Test
    public void denialReason_renameIsNotAllowed() {
        RestoreSnapshotRequest request = restore(ALERTING_CONFIG).renamePattern("(.+)").renameReplacement("restored-$1");
        assertThat(helper.denialReason(request, Set.of(ALERTING_CONFIG)).get(), containsString("Renaming indices is not allowed"));
    }

    @Test
    public void denialReason_renamePatternWithoutReplacementIsNotARename() {
        RestoreSnapshotRequest request = restore(ALERTING_CONFIG).renamePattern("(.+)");
        assertThat(helper.denialReason(request, Set.of(ALERTING_CONFIG)), equalTo(Optional.empty()));
    }

    @Test
    public void isDenialReason_onlyForReasonsFromThisHelper() {
        String reason = helper.denialReason(restore(SECURITY_INDEX), Set.of(SECURITY_INDEX)).get();
        assertThat(SystemIndexRestoreEligibilityHelper.isDenialReason(reason), is(true));
        assertThat(SystemIndexRestoreEligibilityHelper.isDenialReason(".opendistro_security as source index is not allowed"), is(false));
        assertThat(SystemIndexRestoreEligibilityHelper.isDenialReason(null), is(false));
    }
}
