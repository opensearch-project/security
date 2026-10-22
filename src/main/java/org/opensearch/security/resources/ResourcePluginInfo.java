/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import org.opensearch.security.support.ConfigConstants;

/**
 * This class provides information about resource plugins and their associated resource providers and indices.
 * It follows the Singleton pattern to ensure that only one instance of the class exists.
 */
public class ResourcePluginInfo {

    private static final Logger log = LogManager.getLogger(ResourcePluginInfo.class);

    private ResourceSharingClient resourceAccessControlClient;

    private OpensearchDynamicSetting<List<String>> protectedTypesSetting;

    private final Set<ResourceSharingExtension> resourceSharingExtensions = new HashSet<>();

    // type <-> resource provider
    private final Map<String, ResourceProvider> typeToProvider = new HashMap<>();

    // UI: access-level *names* per type
    private final Map<String, LinkedHashSet<String>> typeToAccessLevels = new HashMap<>();

    // AuthZ: resolved (flattened) groups per type
    private final Map<String, FlattenedActionGroups> typeToFlattened = new HashMap<>();

    // default access level per type (for migration)
    private final Map<String, String> typeToDefaultAccessLevel = new HashMap<>();

    // Resource indices of the protected types, recomputed on change because every index and delete operation reads it
    private volatile Set<String> protectedResourceIndices = Collections.emptySet();

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();    // make the updates/reads thread-safe

    public void setProtectedTypesSetting(OpensearchDynamicSetting<List<String>> protectedTypesSetting) {
        lock.writeLock().lock();
        try {
            this.protectedTypesSetting = protectedTypesSetting;
            refreshProtectedResourceIndices(currentProtectedTypes());
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Recomputes {@link #protectedResourceIndices}. Must be called with the write lock held, so a reader cannot observe
     * a snapshot that disagrees with {@link #typeToProvider}.
     *
     * @param protectedTypes the types to treat as protected
     */
    private void refreshProtectedResourceIndices(List<String> protectedTypes) {
        if (protectedTypes == null || protectedTypes.isEmpty()) {
            protectedResourceIndices = Collections.emptySet();
            return;
        }
        protectedResourceIndices = typeToProvider.entrySet()
            .stream()
            .filter(e -> protectedTypes.contains(e.getKey()))
            .map(e -> e.getValue().resourceIndexName())
            .collect(Collectors.toUnmodifiableSet());
    }

    public void setResourceSharingExtensions(Set<ResourceSharingExtension> extensions) {
        lock.writeLock().lock();
        try {
            if (protectedTypesSetting != null) {
                validateProtectedTypes(protectedTypesSetting.getDynamicSettingValue(), extensions);
            }
            validateTypeFields(extensions);
            resourceSharingExtensions.clear();
            typeToProvider.clear();

            // Providers may share a resource index, but must then agree on the workspaces field: DLS filters a single
            // field per index while ingestion uses each provider's declared field, so a disagreement would silently
            // mis-scope read visibility. Reject conflicting non-null declarations at registration.
            Map<String, String> indexToWorkspacesField = new HashMap<>();
            for (ResourceSharingExtension extension : extensions) {
                for (var rp : extension.getResourceProviders()) {
                    // Enforce resource-type unique-ness
                    if (typeToProvider.putIfAbsent(rp.resourceType(), rp) != null) {
                        throw new OpenSearchSecurityException(
                            String.format(
                                "Resource type [%s] is already registered. Please provide a different unique-name for the resource declared by %s.",
                                rp.resourceType(),
                                extension.getClass().getName()
                            )
                        );
                    }

                    String workspacesField = rp.workspacesField();
                    if (workspacesField != null) {
                        String existing = indexToWorkspacesField.putIfAbsent(rp.resourceIndexName(), workspacesField);
                        if (existing != null && !existing.equals(workspacesField)) {
                            throw new OpenSearchSecurityException(
                                String.format(
                                    "Conflicting workspaces fields declared for resource index [%s]: [%s] and [%s]. All providers sharing"
                                        + " an index must declare the same workspaces field (or null to opt out).",
                                    rp.resourceIndexName(),
                                    existing,
                                    workspacesField
                                )
                            );
                        }
                    }
                }
            }
            resourceSharingExtensions.addAll(extensions);
            refreshProtectedResourceIndices(currentProtectedTypes());
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void updateProtectedTypes(List<String> protectedTypes) {
        lock.writeLock().lock();
        try {
            validateProtectedTypes(protectedTypes, resourceSharingExtensions);
            // Rebuild mappings based on the current allowlist
            typeToProvider.clear();

            if (protectedTypes == null || protectedTypes.isEmpty()) {
                refreshProtectedResourceIndices(protectedTypes);
                return;
            }

            for (ResourceSharingExtension extension : resourceSharingExtensions) {
                for (var rp : extension.getResourceProviders()) {
                    final String type = rp.resourceType();
                    if (!protectedTypes.contains(type)) continue;
                    typeToProvider.put(rp.resourceType(), rp);
                }
            }
            refreshProtectedResourceIndices(protectedTypes);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Requires all or none of the registered resource types sharing an index to be protected.
     * Uses every extension, not the protection-filtered provider map, to detect omitted sibling types.
     */
    public void validateProtectedTypes(List<String> protectedTypes) {
        lock.readLock().lock();
        try {
            validateProtectedTypes(protectedTypes, resourceSharingExtensions);
        } finally {
            lock.readLock().unlock();
        }
    }

    /** Rejects a provider with no type field on an index that other providers share, since its documents cannot be told apart. */
    private static void validateTypeFields(Set<ResourceSharingExtension> extensions) {
        Map<String, Set<String>> typesByIndex = new TreeMap<>();
        Map<String, String> untypedByIndex = new HashMap<>();
        for (ResourceSharingExtension extension : extensions) {
            for (ResourceProvider provider : extension.getResourceProviders()) {
                typesByIndex.computeIfAbsent(provider.resourceIndexName(), index -> new TreeSet<>()).add(provider.resourceType());
                if (provider.typeField() == null) {
                    untypedByIndex.put(provider.resourceIndexName(), provider.resourceType());
                }
            }
        }
        for (var entry : untypedByIndex.entrySet()) {
            Set<String> types = typesByIndex.get(entry.getKey());
            if (types.size() > 1) {
                throw new OpenSearchSecurityException(
                    String.format(
                        "Resource type [%s] declares no typeField, but index [%s] holds resource types %s."
                            + " Types that share an index must each declare a typeField.",
                        entry.getValue(),
                        entry.getKey(),
                        types
                    )
                );
            }
        }
    }

    private static void validateProtectedTypes(List<String> protectedTypes, Set<ResourceSharingExtension> extensions) {
        if (protectedTypes == null || protectedTypes.isEmpty()) {
            return;
        }
        Set<String> selected = new HashSet<>(protectedTypes);
        Map<String, Set<String>> typesByIndex = new TreeMap<>();
        for (ResourceSharingExtension extension : extensions) {
            for (ResourceProvider provider : extension.getResourceProviders()) {
                typesByIndex.computeIfAbsent(provider.resourceIndexName(), index -> new TreeSet<>()).add(provider.resourceType());
            }
        }
        for (var entry : typesByIndex.entrySet()) {
            Set<String> types = entry.getValue();
            if (!Collections.disjoint(types, selected) && !selected.containsAll(types)) {
                Set<String> missing = new TreeSet<>(types);
                missing.removeAll(selected);
                throw new IllegalArgumentException(
                    "Setting ["
                        + ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES
                        + "] must include all or none of the resource types "
                        + types
                        + " registered for index ["
                        + entry.getKey()
                        + "]; missing types: "
                        + missing
                );
            }
        }
    }

    /**
     * Extracts the value of a field from the Lucene document backing an {@link Engine.Index} operation.
     * <p>
     * This method iterates over all {@link IndexableField} instances with the given {@code fieldName} on the
     * root document of {@code indexOp}. It returns the first non-{@code null} value, preferring
     * {@link IndexableField#stringValue()} and falling back to decoding {@link IndexableField#binaryValue()}
     * as UTF-8 if present.
     *
     * @param fieldName the name of the field to extract from the index operation's root document; must not be {@code null}
     * @param indexOp   the index operation whose parsed document will be inspected; must not be {@code null}
     * @return the first non-{@code null} string or UTF-8-decoded binary value of the field, or {@code null} if no such value exists
     */
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

    /**
     * Extracts all values of a multi-valued field from the Lucene document backing an {@link Engine.Index} op —
     * e.g. the set of workspace IDs a resource belongs to (see {@link ResourceProvider#workspacesField()}). Unlike
     * {@link #extractFieldFromIndexOp} it collects every {@link IndexableField} for {@code fieldName}, which is how a
     * {@code keyword} array surfaces (one field per element). Values only surface for indexed/stored mappings, not
     * {@code doc_values}-only fields.
     *
     * @param fieldName the multi-valued field to extract; must not be {@code null}
     * @param indexOp   the index op whose parsed document is inspected; must not be {@code null}
     * @return the field's values, or empty if none
     */
    public static Set<String> extractMultiValuedFieldFromIndexOp(String fieldName, Engine.Index indexOp) {
        Set<String> values = new HashSet<>();
        for (IndexableField f : indexOp.parsedDoc().rootDoc().getFields(fieldName)) {
            if (f.stringValue() != null) {
                values.add(f.stringValue());
            } else if (f.binaryValue() != null) { // e.g., BytesRef-backed
                values.add(f.binaryValue().utf8ToString());
            }
        }
        return values;
    }

    /**
     * Resolves the provider of the document an index operation writes, or {@code null} if it is not a resource.
     * See {@link #resolveResourceProvider} for the rule.
     */
    public ResourceProvider getResourceProviderForIndexOp(String resourceIndex, Engine.Index indexOp) {
        return resolveResourceProvider(resourceIndex, field -> extractFieldFromIndexOp(field, indexOp));
    }

    /**
     * Resolves the provider of a document in {@code resourceIndex}: the one provider on the index whose
     * {@link ResourceProvider#matchesResource} accepts the document.
     *
     * @param resourceIndex the index holding the document
     * @param fieldValue    reads a document field by name, or {@code null} when absent
     * @return the provider, or {@code null} if no provider matches, or more than one does
     */
    public ResourceProvider resolveResourceProvider(String resourceIndex, Function<String, String> fieldValue) {
        lock.readLock().lock();
        try {
            ResourceProvider match = null;
            for (ResourceProvider provider : typeToProvider.values()) {
                if (!provider.resourceIndexName().equals(resourceIndex) || !provider.matchesResource(fieldValue)) {
                    continue;
                }
                if (match != null) {
                    log.warn(
                        "A document in index [{}] matches resource types [{}] and [{}]; it is not treated as a resource",
                        resourceIndex,
                        match.resourceType(),
                        provider.resourceType()
                    );
                    return null;
                }
                match = provider;
            }
            return match;
        } finally {
            lock.readLock().unlock();
        }
    }

    /** Whether {@code resourceType} is listed in the protected-types setting. */
    public boolean isProtectedType(String resourceType) {
        List<String> protectedTypes = protectedTypesSetting == null ? null : protectedTypesSetting.getDynamicSettingValue();
        return resourceType != null && protectedTypes != null && protectedTypes.contains(resourceType);
    }

    public Set<ResourceSharingExtension> getResourceSharingExtensions() {
        return ImmutableSet.copyOf(resourceSharingExtensions);
    }

    /**
     * Aggregates {@link ResourceSharingExtension#resolveWorkspacesForUser} across every registered extension into a
     * single trusted set of workspace IDs for the user. Empty if no extension contributes any. Called on the DLS hot
     * path — each extension's implementation is required by contract to be I/O-free.
     *
     * @param user the authenticated user
     * @return the union of workspace IDs contributed by all registered extensions
     */
    public Set<String> resolveWorkspacesForUser(org.opensearch.security.user.User user) {
        lock.readLock().lock();
        try {
            if (resourceSharingExtensions.isEmpty()) {
                return java.util.Collections.emptySet();
            }
            Set<String> securityRoles = user.getSecurityRoles() == null ? java.util.Collections.emptySet() : user.getSecurityRoles();
            Set<String> backendRoles = user.getRoles() == null ? java.util.Collections.emptySet() : user.getRoles();
            Set<String> merged = new HashSet<>();
            for (ResourceSharingExtension extension : resourceSharingExtensions) {
                Set<String> contributed = extension.resolveWorkspacesForUser(user.getName(), securityRoles, backendRoles);
                if (contributed != null && !contributed.isEmpty()) {
                    merged.addAll(contributed);
                }
            }
            return merged;
        } finally {
            lock.readLock().unlock();
        }
    }

    public void setResourceSharingClient(ResourceSharingClient resourceAccessControlClient) {
        this.resourceAccessControlClient = resourceAccessControlClient;
    }

    public ResourceSharingClient getResourceAccessControlClient() {
        return resourceAccessControlClient;
    }

    /** Register/merge access-levels names for a given resource type. */
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

    public void registerAccessLevels(
        String resourceType,
        SecurityDynamicConfiguration<ActionGroupsV7> accessLevels,
        String defaultAccessLevel
    ) {
        if (resourceType == null || accessLevels == null) return;
        lock.writeLock().lock();
        try {
            FlattenedActionGroups flattened = new FlattenedActionGroups(accessLevels);
            typeToFlattened.put(resourceType, flattened);
            typeToAccessLevels.computeIfAbsent(resourceType, k -> new LinkedHashSet<>())
                .addAll(accessLevels.getCEntries().keySet().stream().toList());
            if (defaultAccessLevel != null) {
                typeToDefaultAccessLevel.put(resourceType, defaultAccessLevel);
            }
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

    public String getDefaultAccessLevel(String resourceType) {
        lock.readLock().lock();
        try {
            return typeToDefaultAccessLevel.get(resourceType);
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

    /**
     * Returns the provider-declared workspaces field name for the resource index (see
     * {@link ResourceProvider#workspacesField()}), or {@code null} if no provider on that index declares one.
     * Used by DLS to filter workspace membership on the field a provider actually declares, rather than a fixed name.
     * When multiple providers share an index, the first declared (non-null) field wins.
     */
    /**
     * Returns the workspaces field for the given resource index, or {@code null} if no provider on that index
     * declares one. Providers sharing an index are required to agree on this field — conflicting non-null
     * declarations are rejected at registration (see {@link #setResourceSharingExtensions}) — so the value is
     * unambiguous regardless of map iteration order.
     */
    public String workspacesFieldForIndex(String index) {
        lock.readLock().lock();
        try {
            for (ResourceProvider provider : typeToProvider.values()) {
                if (provider.resourceIndexName().equals(index) && provider.workspacesField() != null) {
                    return provider.workspacesField();
                }
            }
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    public Set<ResourceDashboardInfo> getResourceTypes() {
        lock.readLock().lock();
        try {
            return typeToProvider.keySet()
                .stream()
                .map(
                    s -> new ResourceDashboardInfo(
                        s,
                        Collections.unmodifiableSet(typeToAccessLevels.getOrDefault(s, new LinkedHashSet<>()))
                    )
                )
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

    /**
     * The resource indices of the currently protected types, as an immutable snapshot. Consulted on every index and
     * delete operation in the cluster, so it is not recomputed per call.
     */
    public Set<String> getResourceIndicesForProtectedTypes() {
        return protectedResourceIndices;
    }

    /** The types currently listed as protected, or null before the setting is wired. */
    public List<String> currentProtectedTypes() {
        lock.readLock().lock();
        try {
            return protectedTypesSetting == null ? null : protectedTypesSetting.getDynamicSettingValue();
        } finally {
            lock.readLock().unlock();
        }
    }

    public Set<String> availableAccessLevels() {
        lock.readLock().lock();
        try {
            return typeToAccessLevels.values().stream().flatMap(Set::stream).collect(Collectors.toCollection(LinkedHashSet::new));
        } finally {
            lock.readLock().unlock();
        }
    }

}
