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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;
import org.apache.lucene.index.IndexableField;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.engine.Engine;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.spi.resources.ResourceProvider;
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

    private OpensearchDynamicSetting<List<String>> protectedTypesSetting;

    private final Set<ResourceSharingExtension> resourceSharingExtensions = new HashSet<>();

    // UI: action-group *names* per type
    private final Map<String, LinkedHashSet<String>> typeToAccessLevels = new HashMap<>();

    // AuthZ: resolved (flattened) groups per type
    private final Map<String, FlattenedActionGroups> typeToFlattened = new HashMap<>();

    private final Map<String, ResourceProvider> typeToProvider = new HashMap<>();

    // cache current protected types and their indices
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();    // make the updates/reads thread-safe

    public void setProtectedTypesSetting(OpensearchDynamicSetting<List<String>> protectedTypesSetting) {
        this.protectedTypesSetting = protectedTypesSetting;
    }

    public void setResourceSharingExtensions(Set<ResourceSharingExtension> extensions) {
        lock.writeLock().lock();
        try {
            resourceSharingExtensions.clear();
            typeToProvider.clear();

            // Enforce resource-type unique-ness
            Set<String> resourceTypes = new HashSet<>();
            for (ResourceSharingExtension extension : extensions) {
                for (var rp : extension.getResourceProviders()) {
                    if (!resourceTypes.contains(rp.resourceType())) {
                        // add name seen so far to the resource-types set
                        resourceTypes.add(rp.resourceType());
                        // also cache type->index and index->type mapping
                        typeToProvider.put(rp.resourceType(), rp);
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
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void updateProtectedTypes(List<String> protectedTypes) {
        lock.writeLock().lock();
        try {
            // Rebuild mappings based on the current allowlist
            typeToProvider.clear();

            if (protectedTypes == null || protectedTypes.isEmpty()) {
                // No protected types -> leave maps empty
                return;
            }

            for (ResourceSharingExtension extension : resourceSharingExtensions) {
                for (var rp : extension.getResourceProviders()) {
                    final String type = rp.resourceType();
                    if (!protectedTypes.contains(type)) continue;

                    typeToProvider.put(type, rp);
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public static String extractFieldFromIndexOp(String fieldName, Engine.Index indexOp) {
        String fieldValue = null;
        for (IndexableField f : indexOp.parsedDoc().rootDoc().getFields(fieldName)) {
            if (f.stringValue() != null) {
                fieldValue = f.stringValue();
                break;
            }
            if (f.binaryValue() != null) { // e.g., BytesRef-backed
                fieldValue = f.binaryValue().utf8ToString();
                break;
            }
        }
        return fieldValue;
    }

    public String getResourceTypeForIndexOp(String resourceIndex, Engine.Index indexOp) {
        lock.readLock().lock();
        try {
            // Eagerly use type field from first matching provider of same index as the indexOp
            // If typeField is not present, assume single resource type per index and return type from provider
            var provider = typeToProvider.values()
                .stream()
                .filter(p -> p.resourceIndexName().equals(resourceIndex))
                .findFirst()
                .orElse(null);
            if (provider == null) {
                // should not happen
                return null;
            }
            if (provider.typeField() != null) {
                return extractFieldFromIndexOp(provider.typeField(), indexOp);
            }
            // If `typeField` is not defined, assume single type to index and return type from provider
            return provider.resourceType();
        } finally {
            lock.readLock().unlock();
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
    public record ResourceDashboardInfo(String resourceType, Set<String> accessLevels // names only (for UI)
    ) implements ToXContentObject {
        @Override
        public XContentBuilder toXContent(XContentBuilder b, Params p) throws IOException {
            b.startObject();
            b.field("type", resourceType);
            b.field("access_levels", accessLevels == null ? Collections.emptyList() : accessLevels);
            return b.endObject();
        }
    }

    public void registerAccessLevels(String resourceType, SecurityDynamicConfiguration<ActionGroupsV7> accessLevels) {
        if (resourceType == null || accessLevels == null) return;
        lock.writeLock().lock();
        try {
            FlattenedActionGroups flattened = new FlattenedActionGroups(accessLevels);
            typeToFlattened.put(resourceType, flattened);
            typeToAccessLevels.computeIfAbsent(resourceType, k -> new LinkedHashSet<>())
                .addAll(accessLevels.getCEntries().keySet().stream().toList());
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

    public ResourceProvider getResourceProvider(String type) {
        lock.readLock().lock();
        try {
            return typeToProvider.get(type);
        } finally {
            lock.readLock().unlock();
        }
    }

    public String indexByType(String type) {
        lock.readLock().lock();
        try {
            if (!typeToProvider.containsKey(type)) {
                return null;
            }
            return typeToProvider.get(type).resourceIndexName();
        } finally {
            lock.readLock().unlock();
        }
    }

    public String getParentIdField(String resourceType) {
        lock.readLock().lock();
        try {
            if (!typeToProvider.containsKey(resourceType)) {
                return null;
            }
            return typeToProvider.get(resourceType).parentIdField();
        } finally {
            lock.readLock().unlock();
        }
    }

    public String getParentType(String resourceType) {
        lock.readLock().lock();
        try {
            if (!typeToProvider.containsKey(resourceType)) {
                return null;
            }
            return typeToProvider.get(resourceType).parentType();
        } finally {
            lock.readLock().unlock();
        }
    }

    public Set<ResourceDashboardInfo> getResourceTypes() {
        lock.readLock().lock();
        try {
            return typeToProvider.keySet()
                .stream()
                .map(s -> new ResourceDashboardInfo(s, typeToAccessLevels.get(s)))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        } finally {
            lock.readLock().unlock();
        }
    }

    public Set<String> getResourceIndices() {
        lock.readLock().lock();
        try {
            return typeToProvider.values().stream().map(ResourceProvider::resourceIndexName).collect(Collectors.toSet());
        } finally {
            lock.readLock().unlock();
        }
    }

    public Set<String> getResourceIndicesForProtectedTypes() {
        List<String> resourceTypes = this.protectedTypesSetting.getDynamicSettingValue();
        if (resourceTypes == null || resourceTypes.isEmpty()) {
            return Collections.emptySet();
        }

        lock.readLock().lock();
        try {
            return typeToProvider.entrySet()
                .stream()
                .filter(e -> resourceTypes.contains(e.getKey()))
                .map(e -> e.getValue().resourceIndexName())
                .collect(Collectors.toSet());
        } finally {
            lock.readLock().unlock();
        }
    }

}
// CS-ENFORCE-SINGLE
