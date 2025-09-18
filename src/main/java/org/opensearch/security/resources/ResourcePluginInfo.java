/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

// CS-SUPPRESS-SINGLE: RegexpSingleline get Resource Sharing Extensions
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.spi.resources.ResourceSharingExtension;

/**
 * This class provides information about resource plugins and their associated resource providers and indices.
 * It follows the Singleton pattern to ensure that only one instance of the class exists.
 *
 * @opensearch.experimental
 */
public class ResourcePluginInfo {

    private final Set<ResourceSharingExtension> resourceSharingExtensions = new HashSet<>();

    // type <-> index
    private final Map<String, String> typeToIndex = new HashMap<>();
    private final Map<String, String> indexToType = new HashMap<>();

    // UI: action-group *names* per type
    private final Map<String, LinkedHashSet<String>> typeToGroupNames = new HashMap<>();

    // AuthZ: resolved (flattened) groups per type
    private final Map<String, FlattenedActionGroups> typeToFlattened = new HashMap<>();

    public void setResourceSharingExtensions(Set<ResourceSharingExtension> extensions) {
        resourceSharingExtensions.clear();
        typeToIndex.clear();
        indexToType.clear();
        // Enforce resource-type unique-ness
        Set<String> resourceTypes = new HashSet<>();
        for (ResourceSharingExtension extension : extensions) {
            for (var rp : extension.getResourceProviders()) {
                if (!resourceTypes.contains(rp.resourceType())) {
                    // add name seen so far to the resource-types set
                    resourceTypes.add(rp.resourceType());
                    // also cache type->index and index->type mapping
                    typeToIndex.put(rp.resourceType(), rp.resourceIndexName());
                    indexToType.put(rp.resourceIndexName(), rp.resourceType());
                } else {
                    throw new OpenSearchSecurityException(
                        String.format(
                            "Resource type [%s] is already registered. Please provide a different unique-name for the resource declared by %s.",
                            rp.resourceType(),
                            extension.getClass().getName()
                        )
                    );
                }
            }
        }
        resourceSharingExtensions.addAll(extensions);
    }

    public Set<ResourceSharingExtension> getResourceSharingExtensions() {
        return ImmutableSet.copyOf(resourceSharingExtensions);
    }

    /** Register/merge action-group names for a given resource type. */

    public record ResourceDashboardInfo(String resourceType, String resourceIndexName, Set<String> actionGroups // names only (for UI)
    ) implements ToXContentObject {
        @Override
        public XContentBuilder toXContent(XContentBuilder b, Params p) throws IOException {
            b.startObject();
            b.field("type", resourceType);
            b.field("index", resourceIndexName);
            b.field("action_groups", actionGroups == null ? Collections.emptyList() : actionGroups);
            return b.endObject();
        }
    }

    public void registerActionGroupNames(String resourceType, Collection<String> names) {
        if (resourceType == null || names == null) return;
        typeToGroupNames.computeIfAbsent(resourceType, k -> new LinkedHashSet<>())
            .addAll(names.stream().filter(Objects::nonNull).map(String::trim).filter(s -> !s.isEmpty()).toList());
    }

    public void registerFlattened(String resourceType, FlattenedActionGroups flattened) {
        if (resourceType == null || flattened == null) return;
        typeToFlattened.put(resourceType, flattened);
    }

    public FlattenedActionGroups flattenedForType(String resourceType) {
        return typeToFlattened.getOrDefault(resourceType, FlattenedActionGroups.EMPTY);
    }

    public String typeByIndex(String index) {
        return indexToType.get(index);
    }

    public Set<ResourceDashboardInfo> getResourceTypes() {
        return typeToIndex.entrySet()
            .stream()
            .map(
                e -> new ResourceDashboardInfo(
                    e.getKey(),
                    e.getValue(),
                    Collections.unmodifiableSet(typeToGroupNames.getOrDefault(e.getKey(), new LinkedHashSet<>()))
                )
            )
            .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public Set<String> getResourceIndices() {
        return indexToType.keySet();
    }

}
// CS-ENFORCE-SINGLE
