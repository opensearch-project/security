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
import org.opensearch.common.settings.Settings;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ResourceSharingProtectedResourcesSettingTests {
    private static final String KEY = ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES.getKey();

    private ResourceSharingExtension extension(String type, String index) {
        ResourceProvider provider = mock(ResourceProvider.class);
        when(provider.resourceType()).thenReturn(type);
        when(provider.resourceIndexName()).thenReturn(index);
        // Types sharing an index must each declare a type field
        when(provider.typeField()).thenReturn("type");
        ResourceSharingExtension extension = mock(ResourceSharingExtension.class);
        when(extension.getResourceProviders()).thenReturn(Set.of(provider));
        return extension;
    }

    private Set<ResourceSharingExtension> extensions() {
        // Include providers from different plugins and an independent index.
        return Set.of(extension("monitor", ".shared"), extension("workflow", ".shared"), extension("model", ".models"));
    }

    private Settings settings(String... types) {
        return Settings.builder().putList(KEY, types).build();
    }

    @Test
    public void testStartupRejectsPartialProtection() {
        ResourcePluginInfo info = new ResourcePluginInfo();
        info.setProtectedTypesSetting(new ResourceSharingProtectedResourcesSetting(settings("monitor"), info));
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> info.setResourceSharingExtensions(extensions())
        );
        assertTrue(error.getMessage().contains("index [.shared]"));
        assertTrue(error.getMessage().contains("missing types: [workflow]"));
        assertTrue(info.getResourceSharingExtensions().isEmpty());
    }

    @Test
    public void testStartupAcceptsAllOrNoneAndIndependentIndices() {
        for (List<String> types : List.of(List.<String>of(), List.of("model"), List.of("monitor", "workflow"))) {
            ResourcePluginInfo info = new ResourcePluginInfo();
            info.setProtectedTypesSetting(new ResourceSharingProtectedResourcesSetting(settings(types.toArray(String[]::new)), info));
            info.setResourceSharingExtensions(extensions());
        }
    }

    @Test
    public void testLegacyStartupSettingIsValidated() {
        ResourcePluginInfo info = new ResourcePluginInfo();
        Settings legacy = Settings.builder()
            .putList(ResourceSharingProtectedResourcesSetting.LEGACY_PROTECTED_TYPES.getKey(), "monitor")
            .build();
        info.setProtectedTypesSetting(new ResourceSharingProtectedResourcesSetting(legacy, info));
        assertThrows(IllegalArgumentException.class, () -> info.setResourceSharingExtensions(extensions()));
    }

    @Test
    public void testAddingSiblingProviderRequiresUpdatingProtection() {
        ResourcePluginInfo info = new ResourcePluginInfo();
        info.setProtectedTypesSetting(new ResourceSharingProtectedResourcesSetting(settings("monitor"), info));
        Set<ResourceSharingExtension> original = Set.of(extension("monitor", ".shared"));
        info.setResourceSharingExtensions(original);
        assertThrows(IllegalArgumentException.class, () -> info.setResourceSharingExtensions(extensions()));
        assertEquals(original, info.getResourceSharingExtensions());
        assertEquals(".shared", info.indexByType("monitor"));
    }

    @Test
    public void testInvalidUpdatesPreserveSettingAndProviders() {
        ResourcePluginInfo info = new ResourcePluginInfo();
        ResourceSharingProtectedResourcesSetting setting = new ResourceSharingProtectedResourcesSetting(Settings.EMPTY, info);
        info.setProtectedTypesSetting(setting);
        info.setResourceSharingExtensions(extensions());
        ClusterSettings clusterSettings = new ClusterSettings(Settings.EMPTY, Set.of(setting.getDynamicSetting()));
        setting.registerClusterSettingsChangeListener(clusterSettings);

        assertThrows(IllegalArgumentException.class, () -> clusterSettings.validate(settings("monitor"), true));

        clusterSettings.applySettings(settings("monitor", "workflow"));
        assertThrows(IllegalArgumentException.class, () -> clusterSettings.validateUpdate(settings("monitor")));
        assertThrows(IllegalArgumentException.class, () -> clusterSettings.applySettings(settings("workflow")));
        assertThrows(IllegalArgumentException.class, () -> info.updateProtectedTypes(List.of("monitor")));
        assertEquals(List.of("monitor", "workflow"), setting.getDynamicSettingValue());
        assertEquals(".shared", info.indexByType("monitor"));
        assertEquals(".shared", info.indexByType("workflow"));

        clusterSettings.applySettings(settings());
        assertTrue(setting.getDynamicSettingValue().isEmpty());
        assertTrue(info.getResourceIndices().isEmpty());
        // Validation must still see providers after the protected-provider map has been cleared.
        assertThrows(IllegalArgumentException.class, () -> clusterSettings.validateUpdate(settings("monitor")));
        clusterSettings.applySettings(settings("monitor", "workflow", "model"));
        assertEquals(Set.of(".shared", ".models"), info.getResourceIndices());
    }
}
