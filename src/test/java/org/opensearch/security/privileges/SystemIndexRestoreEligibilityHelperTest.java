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
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecuritySettings;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

public class SystemIndexRestoreEligibilityHelperTest {

    private static final String ALERTING_CONFIG = ".opendistro-alerting-config";
    private static final String REPORTS_DEFINITIONS = ".opendistro-reports-definitions";
    private static final String REPORTS_INSTANCES = ".opendistro-reports-instances";
    private static final String ALERT_HISTORY = ".opendistro-alerting-alert-history-2026.09.24-1";
    private static final String SECURITY_INDEX = ".opendistro_security";

    private final SystemIndexRestoreEligibilityHelper helper = helper(
        Settings.builder()
            .putList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of("all_access", "security_rest_api_access"))
            .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY, List.of(ALERTING_CONFIG, ".opendistro-reports-*"))
            .build()
    );

    private final SystemIndexRestoreEligibilityHelper helperWithDefaults = helper(
        Settings.builder().putList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of("all_access")).build()
    );

    /** Builds a helper whose cluster settings start from the given node settings. */
    private static SystemIndexRestoreEligibilityHelper helper(Settings nodeSettings) {
        return new SystemIndexRestoreEligibilityHelper(
            nodeSettings,
            new ClusterSettings(nodeSettings, Set.of(SecuritySettings.SYSTEM_INDICES_RESTORE_INDICES_SETTING))
        );
    }

    private static RestoreSnapshotRequest restore(String... indices) {
        return new RestoreSnapshotRequest("repo", "snap").indices(indices);
    }

    @Test
    public void isRestAdmin_trueForRestApiRole() {
        assertThat(helper.isRestAdmin(Set.of("all_access")), is(true));
        assertThat(helper.isRestAdmin(Set.of("readall", "security_rest_api_access")), is(true));
    }

    @Test
    public void isRestAdmin_falseForOtherRolesOrNone() {
        assertThat(helper.isRestAdmin(Set.of("readall")), is(false));
        assertThat(helper.isRestAdmin(Set.of()), is(false));
        assertThat(helper.isRestAdmin(null), is(false));
    }

    @Test
    public void isRestAdmin_falseWhenRestApiRolesNotConfigured() {
        SystemIndexRestoreEligibilityHelper unconfigured = helper(Settings.EMPTY);
        assertThat(unconfigured.isRestAdmin(Set.of("all_access")), is(false));
    }

    @Test
    public void clusterSettingsUpdate_replacesEligibleIndicesAndDenialMessage() {
        Settings nodeSettings = Settings.builder()
            .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY, List.of(ALERTING_CONFIG))
            .build();
        ClusterSettings clusterSettings = new ClusterSettings(
            nodeSettings,
            Set.of(SecuritySettings.SYSTEM_INDICES_RESTORE_INDICES_SETTING)
        );
        SystemIndexRestoreEligibilityHelper dynamic = new SystemIndexRestoreEligibilityHelper(nodeSettings, clusterSettings);
        assertThat(dynamic.isEligible(REPORTS_DEFINITIONS), is(false));

        clusterSettings.applySettings(
            Settings.builder().putList(ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY, List.of(REPORTS_DEFINITIONS)).build()
        );

        assertThat(dynamic.isEligible(REPORTS_DEFINITIONS), is(true));
        assertThat(dynamic.isEligible(ALERTING_CONFIG), is(false));
        assertThat(
            dynamic.denialReason(restore(ALERTING_CONFIG), Set.of(ALERTING_CONFIG)).orElseThrow(),
            containsString("Restorable system indices: [" + REPORTS_DEFINITIONS + "]")
        );
    }

    @Test
    public void isEligible_matchesConfiguredIndicesAndPatterns() {
        assertThat(helper.isEligible(ALERTING_CONFIG), is(true));
        assertThat(helper.isEligible(REPORTS_DEFINITIONS), is(true));
        assertThat(helper.isEligible(ALERT_HISTORY), is(false));
        assertThat(helper.isEligible(SECURITY_INDEX), is(false));
    }

    @Test
    public void isEligible_defaultListCoversConfirmedPluginIndices() {
        for (final String index : ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_DEFAULT) {
            assertThat(index, helperWithDefaults.isEligible(index), is(true));
        }
        assertThat(helperWithDefaults.isEligible(REPORTS_DEFINITIONS), is(false));
        assertThat(helperWithDefaults.isEligible(SECURITY_INDEX), is(false));
    }

    @Test
    public void denialReason_emptyForExplicitAllowlistedIndices() {
        RestoreSnapshotRequest request = restore(ALERTING_CONFIG, REPORTS_DEFINITIONS, "my-data");
        assertThat(helper.denialReason(request, Set.of(ALERTING_CONFIG, REPORTS_DEFINITIONS)), equalTo(Optional.empty()));
        assertThat(helper.isRestorableByRestAdmin(request, ALERTING_CONFIG), is(true));
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
        SystemIndexRestoreEligibilityHelper noneConfigured = helper(
            Settings.builder().putList(ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY, List.of()).build()
        );
        Optional<String> reason = noneConfigured.denialReason(restore(ALERTING_CONFIG), Set.of(ALERTING_CONFIG));
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
        assertThat(helper.isRestorableByRestAdmin(restore("*"), ALERTING_CONFIG), is(false));
    }

    @Test
    public void denialReason_patternSameAsRestorableEntryIsNamed() {
        RestoreSnapshotRequest request = restore(".opendistro-reports-*");
        assertThat(helper.denialReason(request, Set.of(REPORTS_DEFINITIONS, REPORTS_INSTANCES)), equalTo(Optional.empty()));
        assertThat(helper.isRestorableByRestAdmin(request, REPORTS_DEFINITIONS), is(true));
    }

    @Test
    public void denialReason_patternNarrowerThanRestorableEntryIsNamed() {
        assertThat(helper.denialReason(restore(".opendistro-reports-def*"), Set.of(REPORTS_DEFINITIONS)), equalTo(Optional.empty()));
    }

    @Test
    public void denialReason_patternBroaderThanRestorableEntryIsNotNamed() {
        Optional<String> reason = helper.denialReason(restore(".opendistro-reports*"), Set.of(REPORTS_DEFINITIONS));
        assertThat(
            reason.get(),
            equalTo(
                "System index restore denied: System indices ["
                    + REPORTS_DEFINITIONS
                    + "] must be named explicitly in the restore request, or matched by a pattern that is no broader than an entry of "
                    + ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY
                    + "."
            )
        );
    }

    @Test
    public void denialReason_patternNamesOnlyTheIndicesItMatches() {
        RestoreSnapshotRequest request = restore(".opendistro-reports-inst*", "*");
        Optional<String> reason = helper.denialReason(request, Set.of(REPORTS_DEFINITIONS, REPORTS_INSTANCES));
        assertThat(reason.get(), containsString("[" + REPORTS_DEFINITIONS + "] must be named explicitly"));
    }

    @Test
    public void denialReason_matchAllPatternIsNamedWhenSameAsRestorableEntry() {
        SystemIndexRestoreEligibilityHelper restoreAll = helper(
            Settings.builder()
                .putList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of("all_access"))
                .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY, List.of("*"))
                .build()
        );
        assertThat(restoreAll.denialReason(restore("*"), Set.of(ALERTING_CONFIG)), equalTo(Optional.empty()));
        assertThat(restoreAll.denialReason(restore("**"), Set.of(ALERTING_CONFIG)).get(), containsString("must be named explicitly"));
        assertThat(restoreAll.denialReason(restore(ALERTING_CONFIG), Set.of(ALERTING_CONFIG)), equalTo(Optional.empty()));
    }

    @Test
    public void denialReason_restorableEntryOfOnlyStarAllowsNoPatterns() {
        SystemIndexRestoreEligibilityHelper restoreAll = helper(
            Settings.builder()
                .putList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of("all_access"))
                .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY, List.of("*"))
                .build()
        );
        assertThat(restoreAll.denialReason(restore(".*"), Set.of(ALERTING_CONFIG)).get(), containsString("must be named explicitly"));
        assertThat(
            restoreAll.denialReason(restore(".opendistro-alerting-*"), Set.of(ALERTING_CONFIG)).get(),
            containsString("must be named explicitly")
        );
    }

    @Test
    public void denialReason_restorableEntryWithLeadingStarAllowsOnlyTheSameText() {
        SystemIndexRestoreEligibilityHelper leadingStar = helper(
            Settings.builder()
                .putList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, List.of("all_access"))
                .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY, List.of("*-config*"))
                .build()
        );
        assertThat(leadingStar.denialReason(restore("*-config*"), Set.of(ALERTING_CONFIG)), equalTo(Optional.empty()));
        assertThat(
            leadingStar.denialReason(restore("*-config"), Set.of(ALERTING_CONFIG)).get(),
            containsString("must be named explicitly")
        );
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
