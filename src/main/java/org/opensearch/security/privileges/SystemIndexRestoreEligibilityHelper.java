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

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

/**
 * Decides whether a security-admin may restore system indices from a snapshot.
 *
 * <p>A security-admin is a caller holding a role listed in {@code plugins.security.restapi.roles_enabled}. Such a caller
 * may restore a system index only when all of the following hold for the request:
 * <ol>
 *   <li>the index matches {@code plugins.security.system_indices.restore.indices} (empty by default),</li>
 *   <li>the index is named explicitly in the request, not matched by a wildcard, so restoring system indices is always
 *       an intentional act and never a side effect of "restore everything",</li>
 *   <li>the request does not rename indices, so a system index cannot be restored under a regular name (escaping system
 *       index protection) and a regular index cannot be restored under a system index name.</li>
 * </ol>
 * Any violation denies the whole request with a reason that tells the caller what to change. This is an additional path
 * next to the existing {@code system:admin/system_index} permission, which is unaffected.
 *
 * <p>Superadmin (admin certificate) bypasses privilege evaluation entirely and is not affected.
 */
public final class SystemIndexRestoreEligibilityHelper {

    /**
     * Prefix of every denial reason produced here; lets the 403 returned to the caller carry the reason.
     */
    private static final String DENIAL_PREFIX = "System index restore denied: ";

    private final WildcardMatcher securityAdminRoles;
    private final List<String> restorableIndices;
    private final WildcardMatcher restorableIndicesMatcher;

    public SystemIndexRestoreEligibilityHelper(final Settings settings) {
        this.securityAdminRoles = WildcardMatcher.from(settings.getAsList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED));
        this.restorableIndices = settings.getAsList(
            ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_KEY,
            ConfigConstants.SECURITY_SYSTEM_INDICES_RESTORE_INDICES_DEFAULT
        );
        this.restorableIndicesMatcher = WildcardMatcher.from(restorableIndices);
    }

    /**
     * @return true if the caller holds at least one role listed in {@code plugins.security.restapi.roles_enabled}
     */
    public boolean isSecurityAdmin(final Collection<String> mappedRoles) {
        return mappedRoles != null && !mappedRoles.isEmpty() && securityAdminRoles.matchAny(mappedRoles);
    }

    /**
     * @return true if the index matches {@code plugins.security.system_indices.restore.indices}
     */
    boolean isEligible(final String index) {
        return restorableIndicesMatcher.test(index);
    }

    /**
     * @return true if a security-admin may restore this single system index with this request
     */
    public boolean isRestorableBySecurityAdmin(final RestoreSnapshotRequest request, final String systemIndex) {
        return denialReason(request, Set.of(systemIndex)).isEmpty();
    }

    /**
     * Checks a security-admin's restore request against the rules in the class description.
     *
     * @param request the restore request
     * @param systemIndices the system indices the request restores (target names)
     * @return empty if the request may proceed, otherwise an actionable reason for the denial
     */
    public Optional<String> denialReason(final RestoreSnapshotRequest request, final Collection<String> systemIndices) {
        if (systemIndices == null || systemIndices.isEmpty()) {
            return Optional.empty();
        }
        if (isRename(request)) {
            return denial("Renaming indices is not allowed when restoring system indices " + sorted(systemIndices) + ".");
        }
        final Set<String> nonEligible = systemIndices.stream().filter(index -> !isEligible(index)).collect(Collectors.toSet());
        if (!nonEligible.isEmpty()) {
            String message = "System indices " + sorted(nonEligible) + " are not eligible for restore.";
            if (!restorableIndices.isEmpty()) {
                message += " Restorable system indices: " + restorableIndices + ".";
            }
            return denial(message);
        }
        final List<String> named = request.indices() == null ? List.of() : Arrays.asList(request.indices());
        final Set<String> notNamed = systemIndices.stream().filter(index -> !named.contains(index)).collect(Collectors.toSet());
        if (!notNamed.isEmpty()) {
            return denial(
                "System indices " + sorted(notNamed) + " must be named explicitly in the restore request, not matched by a wildcard."
            );
        }
        return Optional.empty();
    }

    /**
     * @return true if the reason was produced by {@link #denialReason}, so it may be shown to the caller
     */
    public static boolean isDenialReason(final String reason) {
        return reason != null && reason.startsWith(DENIAL_PREFIX);
    }

    private static Optional<String> denial(final String message) {
        return Optional.of(DENIAL_PREFIX + message);
    }

    private static boolean isRename(final RestoreSnapshotRequest request) {
        return request.renamePattern() != null && request.renameReplacement() != null;
    }

    private static Set<String> sorted(final Collection<String> indices) {
        return new TreeSet<>(indices);
    }
}
