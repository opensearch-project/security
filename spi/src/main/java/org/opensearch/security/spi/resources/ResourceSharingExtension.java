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
     * Returns the set of workspace IDs the given user is a member of. Called on the privilege hot path when the
     * security plugin builds the DLS filter for a search over a resource-sharing-protected index: each returned ID
     * becomes a {@code workspace:<id>} DLS principal, which intersects the {@code workspace:<id>} principals
     * denormalized onto resources that belong to those workspaces (see {@code ResourceSharing#getAllPrincipals}).
     *
     * <p><b>Contract</b> — required for security-sensitive correctness:
     * <ul>
     *   <li>The returned set MUST come from a trusted, server-set source that the requesting user cannot assert
     *       (e.g. resolved at authentication time or from a plugin-owned index), NOT from user-influenceable
     *       inputs like JWT/proxy claims. The result grants read visibility, so trusting user-controlled input
     *       would enable a privilege-escalation vector.</li>
     *   <li>The call MUST be I/O-free — this runs on the privilege hot path. Resolve membership eagerly at
     *       authentication time (or maintain an in-memory cache keyed by user identity) rather than issuing a
     *       cluster call here.</li>
     * </ul>
     *
     * <p>The default returns an empty set, which disables workspace-based DLS visibility for the plugin. That is
     * intentional and safe: only plugins that own an authoritative workspace-membership source should override.
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
