/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

/** Resource providers and extensions for resource-sharing unit tests. */
public final class ResourceProviderFixtures {

    /** The index alerting stores monitors and workflows in. */
    public static final String ALERTING_INDEX = ".alerting-config";

    private ResourceProviderFixtures() {}

    /**
     * A provider whose documents hold its type name in {@code typeField}.
     *
     * @param typeField the type field, or {@code null} for an untyped provider
     * @return the provider
     */
    public static ResourceProvider provider(String type, String index, String typeField) {
        return new Provider(type, index, typeField, null);
    }

    /**
     * A provider whose documents hold {@code storedValue} in {@code typeField}, as alerting's workflows hold "workflow".
     *
     * @return the provider
     */
    public static ResourceProvider provider(String type, String index, String typeField, String storedValue) {
        return new Provider(type, index, typeField, storedValue);
    }

    private record Provider(String resourceType, String resourceIndexName, String typeField, String storedValue)
        implements
            ResourceProvider {
        @Override
        public boolean matchesResource(Function<String, String> fieldValue) {
            return storedValue == null
                ? ResourceProvider.super.matchesResource(fieldValue)
                : storedValue.equals(fieldValue.apply(typeField));
        }
    }

    /**
     * An extension that registers {@code providers} in the given order.
     *
     * @return the extension
     */
    public static ResourceSharingExtension extension(ResourceProvider... providers) {
        return new ResourceSharingExtension() {
            @Override
            public Set<ResourceProvider> getResourceProviders() {
                return new LinkedHashSet<>(List.of(providers));
            }

            @Override
            public void assignResourceSharingClient(ResourceSharingClient client) {}
        };
    }

    /**
     * alerting's two providers as alerting declares them: workflow documents hold "workflow", not the type name.
     *
     * @return the extension
     */
    public static ResourceSharingExtension alertingExtension() {
        return extension(
            provider("monitor", ALERTING_INDEX, "monitor.type"),
            provider("alerting-workflow", ALERTING_INDEX, "workflow.type", "workflow")
        );
    }
}
