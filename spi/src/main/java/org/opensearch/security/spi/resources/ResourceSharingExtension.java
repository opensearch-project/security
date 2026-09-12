/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.util.Collections;
import java.util.Set;

import org.opensearch.common.Nullable;
import org.opensearch.security.spi.SecurityConfigExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

/**
 * This interface should be implemented by all the plugins that define one or more resources and need access control over those resources.
 * Extends {@link SecurityConfigExtension} so resource-sharing plugins can also contribute static security configuration
 * (e.g. default roles via {@code default-roles.yml}).
 *
 * @opensearch.experimental
 */
public interface ResourceSharingExtension extends SecurityConfigExtension {

    /**
     * Returns the set of {@link ResourceProvider} instances for the resources defined by the plugin.
     * Only in the case where plugin defines multiple resources, will there be more than one resource provider
    *
     * @return the set of ResourceProvider instances
     */
    Set<ResourceProvider> getResourceProviders();

    /**
     * Assigns the ResourceSharingClient to the resource plugin. Plugins can then utilize this to call the methods for access control.
     * When the resource-sharing feature is disabled, this method is called with {@code null} to clear the client reference.
     * @param client the ResourceSharingClient instance, or {@code null} when the feature is disabled
     */
    void assignResourceSharingClient(@Nullable ResourceSharingClient client);

    /**
     * Returns the workspace IDs the user is a member of. Called on the privilege hot path when building the DLS filter:
     * the returned IDs are matched against each resource's own {@code workspaces} field (not denormalized into
     * {@code all_shared_principals}).
     *
     * <p><b>Contract</b> (security-sensitive):
     * <ul>
     *   <li>MUST come from a trusted, server-set source the user cannot assert (e.g. resolved at authentication time),
     *       never from user-influenceable input like JWT/proxy claims — the result grants read visibility.</li>
     *   <li>MUST be I/O-free (privilege hot path): resolve eagerly at authentication time or from an in-memory cache.</li>
     * </ul>
     *
     * <p>Defaults to an empty set (workspace-based visibility disabled); only plugins owning an authoritative
     * membership source should override.
     *
     * @param username     the authenticated user's name; never {@code null}
     * @param securityRoles the user's security roles; never {@code null}, may be empty
     * @param backendRoles the user's backend roles; never {@code null}, may be empty
     * @return the trusted workspace IDs the user belongs to, or an empty set if none / not implemented
     */
    default Set<String> resolveWorkspacesForUser(String username, Set<String> securityRoles, Set<String> backendRoles) {
        return Collections.emptySet();
    }
}
