/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.settings;

import java.util.List;
import java.util.Set;

import org.junit.Test;

import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.SettingUpgrader;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.security.support.ConfigConstants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Covers the migration path from the pre-graduation resource sharing setting names to the current ones:
 * the current settings fall back to the old keys, and the setting upgraders rewrite the old keys in the
 * cluster state.
 */
public class ResourceSharingSettingMigrationTests {

    private static final String LEGACY_ENABLED = ConfigConstants.OPENSEARCH_LEGACY_RESOURCE_SHARING_ENABLED;
    private static final String CURRENT_ENABLED = ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
    private static final String LEGACY_TYPES = ConfigConstants.OPENSEARCH_LEGACY_RESOURCE_SHARING_PROTECTED_TYPES;
    private static final String CURRENT_TYPES = ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES;

    private ClusterSettings clusterSettings() {
        final Set<Setting<?>> registered = Set.of(
            ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED,
            ResourceSharingFeatureFlagSetting.LEGACY_RESOURCE_SHARING_ENABLED,
            ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES,
            ResourceSharingProtectedResourcesSetting.LEGACY_PROTECTED_TYPES
        );
        final Set<SettingUpgrader<?>> upgraders = Set.of(
            ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED_UPGRADER,
            ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES_UPGRADER
        );
        return new ClusterSettings(Settings.EMPTY, registered, upgraders);
    }

    @Test
    public void testFeatureFlagDefaultsToDisabled() {
        assertFalse(ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED.get(Settings.EMPTY));
    }

    @Test
    public void testFeatureFlagReadsCurrentKey() {
        final Settings settings = Settings.builder().put(CURRENT_ENABLED, true).build();
        assertTrue(ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED.get(settings));
    }

    @Test
    public void testFeatureFlagFallsBackToLegacyKey() {
        final Settings settings = Settings.builder().put(LEGACY_ENABLED, true).build();
        assertTrue(ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED.get(settings));
    }

    @Test
    public void testCurrentKeyWinsOverLegacyKey() {
        final Settings settings = Settings.builder().put(LEGACY_ENABLED, true).put(CURRENT_ENABLED, false).build();
        assertFalse(ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED.get(settings));
    }

    @Test
    public void testProtectedTypesFallsBackToLegacyKey() {
        final Settings settings = Settings.builder().putList(LEGACY_TYPES, List.of("sample-resource", "ml-model-group")).build();
        assertEquals(List.of("sample-resource", "ml-model-group"), ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES.get(settings));
    }

    @Test
    public void testProtectedTypesCurrentKeyWinsOverLegacyKey() {
        final Settings settings = Settings.builder()
            .putList(LEGACY_TYPES, List.of("stale-type"))
            .putList(CURRENT_TYPES, List.of("sample-resource"))
            .build();
        assertEquals(List.of("sample-resource"), ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES.get(settings));
    }

    @Test
    public void testUpgradersTargetTheLegacySettings() {
        assertEquals(LEGACY_ENABLED, ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED_UPGRADER.getSetting().getKey());
        assertEquals(CURRENT_ENABLED, ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED_UPGRADER.getKey(LEGACY_ENABLED));
        assertEquals(LEGACY_TYPES, ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES_UPGRADER.getSetting().getKey());
        assertEquals(CURRENT_TYPES, ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES_UPGRADER.getKey(LEGACY_TYPES));
    }

    @Test
    public void testUpgradeSettingsRewritesLegacyKeys() {
        final Settings upgraded = clusterSettings().upgradeSettings(
            Settings.builder().put(LEGACY_ENABLED, true).putList(LEGACY_TYPES, List.of("sample-resource")).build()
        );

        assertFalse("legacy feature flag key should not survive the upgrade", upgraded.hasValue(LEGACY_ENABLED));
        assertFalse("legacy protected types key should not survive the upgrade", upgraded.hasValue(LEGACY_TYPES));
        assertEquals("true", upgraded.get(CURRENT_ENABLED));
        assertEquals(List.of("sample-resource"), upgraded.getAsList(CURRENT_TYPES));
    }

    @Test
    public void testUpgradeSettingsLeavesCurrentKeysAlone() {
        final Settings original = Settings.builder().put(CURRENT_ENABLED, true).putList(CURRENT_TYPES, List.of("sample-resource")).build();

        assertEquals(original, clusterSettings().upgradeSettings(original));
    }

    @Test
    public void testLegacyKeysPassNodeSettingValidation() {
        // SettingsModule validates node settings from opensearch.yml against the registered settings, and an
        // unrecognized key is what stops a node from starting. Registering the pre-graduation settings is what
        // keeps such a node startable.
        clusterSettings().validate(
            Settings.builder().put(LEGACY_ENABLED, true).putList(LEGACY_TYPES, List.of("sample-resource")).build(),
            true
        );
    }

    @Test
    public void testGenuinelyUnknownKeyStillFailsValidation() {
        // Negative control for the check above: validation must still reject a key nothing registers.
        final Settings settings = Settings.builder().put("plugins.security.experimental.resource_sharing.nonexistent", true).build();
        assertThrows(SettingsException.class, () -> clusterSettings().validate(settings, true));
    }

    @Test
    public void testLegacySettingsAreMarkedDeprecated() {
        assertTrue(ResourceSharingFeatureFlagSetting.LEGACY_RESOURCE_SHARING_ENABLED.isDeprecated());
        assertTrue(ResourceSharingProtectedResourcesSetting.LEGACY_PROTECTED_TYPES.isDeprecated());
    }
}
