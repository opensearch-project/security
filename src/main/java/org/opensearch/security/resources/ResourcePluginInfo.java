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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

/**
 * This class provides information about resource plugins and their associated resource providers and indices.
 * It follows the Singleton pattern to ensure that only one instance of the class exists.
 *
 * @opensearch.experimental
 */
public class ResourcePluginInfo {

    private ResourceSharingClient resourceAccessControlClient;

    private OpensearchDynamicSetting<List<String>> resourceSharingProtectedTypesSetting;

    private final Set<ResourceSharingExtension> resourceSharingExtensions = new HashSet<>();

    // type <-> index
    private final Map<String, String> typeToIndex = new HashMap<>();

    // UI: action-group *names* per type
    private final Map<String, LinkedHashSet<String>> typeToGroupNames = new HashMap<>();

    // AuthZ: resolved (flattened) groups per type
    private final Map<String, FlattenedActionGroups> typeToFlattened = new HashMap<>();

    // cache current protected types and their indices
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();    // make the updates/reads thread-safe
    private Set<String> currentProtectedTypes = Collections.emptySet();          // snapshot of last set
    private Set<String> cachedProtectedTypeIndices = Collections.emptySet();     // precomputed indices

    public void setResourceSharingProtectedTypesSetting(OpensearchDynamicSetting<List<String>> resourceSharingProtectedTypesSetting) {
        this.resourceSharingProtectedTypesSetting = resourceSharingProtectedTypesSetting;
    }

    public void setResourceSharingExtensions(Set<ResourceSharingExtension> extensions) {
        lock.writeLock().lock();
        try {
            resourceSharingExtensions.clear();
            typeToIndex.clear();

            // Enforce resource-type unique-ness
            Set<String> resourceTypes = new HashSet<>();
            for (ResourceSharingExtension extension : extensions) {
                for (var rp : extension.getResourceProviders()) {
                    if (!resourceTypes.contains(rp.resourceType())) {
                        // add name seen so far to the resource-types set
                        resourceTypes.add(rp.resourceType());
                        // also cache type->index and index->type mapping
                        typeToIndex.put(rp.resourceType(), rp.resourceIndexName());
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

            // Whenever providers change, invalidate protected caches so next update refreshes them
            currentProtectedTypes = Collections.emptySet();
            cachedProtectedTypeIndices = Collections.emptySet();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void updateProtectedTypes(List<String> protectedTypes) {
        lock.writeLock().lock();
        try {
            // Rebuild mappings based on the current allowlist
            typeToIndex.clear();

            if (protectedTypes == null || protectedTypes.isEmpty()) {
                // No protected types -> leave maps empty
                currentProtectedTypes = Collections.emptySet();
                cachedProtectedTypeIndices = Collections.emptySet();
                return;
            }

            // Cache current protected set as an unmodifiable snapshot
            currentProtectedTypes = Collections.unmodifiableSet(new LinkedHashSet<>(protectedTypes));

            for (ResourceSharingExtension extension : resourceSharingExtensions) {
                for (var rp : extension.getResourceProviders()) {
                    final String type = rp.resourceType();
                    if (!currentProtectedTypes.contains(type)) continue;

                    final String index = rp.resourceIndexName();
                    typeToIndex.put(type, index);
                }
            }

            // pre-compute indices for current protected set
            cachedProtectedTypeIndices = Collections.unmodifiableSet(new LinkedHashSet<>(typeToIndex.values()));
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Set<ResourceSharingExtension> getResourceSharingExtensions() {
        return ImmutableSet.copyOf(resourceSharingExtensions);
    }

    public void setResourceSharingClient(ResourceSharingClient resourceAccessControlClient) {
        this.resourceAccessControlClient = resourceAccessControlClient;
    }

    public ResourceSharingClient getResourceAccessControlClient() {
        return resourceAccessControlClient;
    }

    /** Register/merge action-group names for a given resource type. */
    public record ResourceDashboardInfo(String resourceType, Set<String> actionGroups // names only (for UI)
    ) implements ToXContentObject {
        @Override
        public XContentBuilder toXContent(XContentBuilder b, Params p) throws IOException {
            b.startObject();
            b.field("type", resourceType);
            b.field("action_groups", actionGroups == null ? Collections.emptyList() : actionGroups);
            return b.endObject();
        }
    }

    public void registerActionGroupNames(String resourceType, Collection<String> names) {
        if (resourceType == null || names == null) return;
        lock.writeLock().lock();
        try {
            typeToGroupNames.computeIfAbsent(resourceType, k -> new LinkedHashSet<>())
                .addAll(names.stream().filter(Objects::nonNull).map(String::trim).filter(s -> !s.isEmpty()).toList());
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void registerFlattened(String resourceType, FlattenedActionGroups flattened) {
        if (resourceType == null || flattened == null) return;
        lock.writeLock().lock();
        try {
            typeToFlattened.put(resourceType, flattened);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public FlattenedActionGroups flattenedForType(String resourceType) {
        lock.readLock().lock();
        try {
            return typeToFlattened.getOrDefault(resourceType, FlattenedActionGroups.EMPTY);
        } finally {
            lock.readLock().unlock();
        }
    }

    public String indexByType(String type) {
        lock.readLock().lock();
        try {
            return typeToIndex.get(type);
        } finally {
            lock.readLock().unlock();
        }
    }

    public Set<String> typesByIndex(String index) {
        lock.readLock().lock();
        try {
            return typeToIndex.entrySet()
                .stream()
                .filter(entry -> Objects.equals(entry.getValue(), index))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
        } finally {
            lock.readLock().unlock();
        }
    }

    public Set<ResourceDashboardInfo> getResourceTypes() {
        lock.readLock().lock();
        try {
            return typeToIndex.keySet()
                .stream()
                .map(
                    s -> new ResourceDashboardInfo(s, Collections.unmodifiableSet(typeToGroupNames.getOrDefault(s, new LinkedHashSet<>())))
                )
                .collect(Collectors.toCollection(LinkedHashSet::new));
        } finally {
            lock.readLock().unlock();
        }
    }

    public Set<String> getResourceIndices() {
        lock.readLock().lock();
        try {
            return new HashSet<>(typeToIndex.values());
        } finally {
            lock.readLock().unlock();
        }
    }

    public Set<String> getResourceIndicesForProtectedTypes() {
        List<String> resourceTypes = this.resourceSharingProtectedTypesSetting.getDynamicSettingValue();
        if (resourceTypes == null || resourceTypes.isEmpty()) {
            return Collections.emptySet();
        }

        lock.readLock().lock();
        try {
            // If caller is asking for the current protected set, return the cache
            if (new LinkedHashSet<>(resourceTypes).equals(currentProtectedTypes)) {
                return cachedProtectedTypeIndices;
            }

            return typeToIndex.entrySet()
                .stream()
                .filter(e -> resourceTypes.contains(e.getKey()))
                .map(Map.Entry::getValue)
                .collect(Collectors.toSet());
        } finally {
            lock.readLock().unlock();
        }
    }

}
// CS-ENFORCE-SINGLE
