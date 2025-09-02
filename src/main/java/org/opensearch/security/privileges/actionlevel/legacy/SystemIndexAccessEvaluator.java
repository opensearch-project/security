/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.privileges.actionlevel.legacy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.RealtimeRequest;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.common.regex.Regex;
import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexRegistry;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.IndicesRequestModifier;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

import static org.opensearch.security.privileges.actionlevel.legacy.PrivilegesEvaluator.isClusterPermissionStatic;

/**
 * This class performs authorization on requests targeting system indices
 * NOTE:
 * - The term `protected system indices` used here translates to system indices
 *   which have an added layer of security and cannot be accessed by anyone except Super Admin
 */
public class SystemIndexAccessEvaluator {

    Logger log = LogManager.getLogger(this.getClass());

    private final String securityIndex;
    private final AuditLog auditLog;
    private final boolean filterSecurityIndex;
    // for system-indices configuration
    private final WildcardMatcher systemIndexMatcher;
    private final WildcardMatcher deniedActionsMatcher;

    private final boolean isSystemIndexEnabled;
    private final boolean isSystemIndexPermissionEnabled;
    private final static ImmutableSet<String> SYSTEM_INDEX_PERMISSION_SET = ImmutableSet.of(ConfigConstants.SYSTEM_INDEX_PERMISSION);
    private final IndicesRequestModifier indicesRequestModifier = new IndicesRequestModifier();

    public SystemIndexAccessEvaluator(final Settings settings, AuditLog auditLog) {
        this.securityIndex = settings.get(
            ConfigConstants.SECURITY_CONFIG_INDEX_NAME,
            ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX
        );
        this.auditLog = auditLog;
        this.filterSecurityIndex = settings.getAsBoolean(ConfigConstants.SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS, false);
        this.systemIndexMatcher = WildcardMatcher.from(
            settings.getAsList(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, ConfigConstants.SECURITY_SYSTEM_INDICES_DEFAULT)
        );

        this.isSystemIndexEnabled = settings.getAsBoolean(
            ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY,
            ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_DEFAULT
        );
        final boolean restoreSecurityIndexEnabled = settings.getAsBoolean(
            ConfigConstants.SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED,
            false
        );

        final List<String> deniedActionPatternsList = deniedActionPatterns();

        final List<String> deniedActionPatternsListNoSnapshot = new ArrayList<>(deniedActionPatternsList);
        deniedActionPatternsListNoSnapshot.add("indices:admin/close*");
        deniedActionPatternsListNoSnapshot.add("cluster:admin/snapshot/restore*");

        deniedActionsMatcher = WildcardMatcher.from(
            restoreSecurityIndexEnabled ? deniedActionPatternsList : deniedActionPatternsListNoSnapshot
        );
        isSystemIndexPermissionEnabled = settings.getAsBoolean(
            ConfigConstants.SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY,
            ConfigConstants.SECURITY_SYSTEM_INDICES_PERMISSIONS_DEFAULT
        );
    }

    private static List<String> deniedActionPatterns() {
        final List<String> securityIndexDeniedActionPatternsList = new ArrayList<>();
        securityIndexDeniedActionPatternsList.add("indices:data/write*");
        securityIndexDeniedActionPatternsList.add("indices:admin/delete*");
        securityIndexDeniedActionPatternsList.add("indices:admin/mapping/delete*");
        securityIndexDeniedActionPatternsList.add("indices:admin/mapping/put*");
        securityIndexDeniedActionPatternsList.add("indices:admin/freeze*");
        securityIndexDeniedActionPatternsList.add("indices:admin/settings/update*");
        securityIndexDeniedActionPatternsList.add("indices:admin/aliases");
        return securityIndexDeniedActionPatternsList;
    }

    public PrivilegesEvaluatorResponse evaluate(
        final ActionRequest request,
        final Task task,
        final String action,
        final OptionallyResolvedIndices requestedResolved,
        final PrivilegesEvaluationContext context,
        final ActionPrivileges actionPrivileges,
        final User user
    ) {
        boolean containsSystemIndex = requestedResolved.local().containsAny(this::isSystemIndex);

        PrivilegesEvaluatorResponse response = evaluateSystemIndicesAccess(
            action,
            requestedResolved,
            request,
            task,
            context,
            actionPrivileges,
            user,
            containsSystemIndex
        );

        if (response == null || response.isAllowed()) {
            if (containsSystemIndex) {

                if (request instanceof SearchRequest) {
                    ((SearchRequest) request).requestCache(Boolean.FALSE);
                    if (log.isDebugEnabled()) {
                        log.debug("Disable search request cache for this request");
                    }
                }

                if (request instanceof RealtimeRequest) {
                    ((RealtimeRequest) request).realtime(Boolean.FALSE);
                    if (log.isDebugEnabled()) {
                        log.debug("Disable realtime for this request");
                    }
                }
            }
        }

        return response;
    }

    private boolean isSystemIndex(String index) {
        if (this.securityIndex.equals(index)) {
            return true;
        }

        if (this.isSystemIndexEnabled) {
            return this.systemIndexMatcher.test(index) || SystemIndexRegistry.matchesSystemIndexPattern(index);
        } else {
            return false;
        }
    }

    /**
     * Is the current action allowed to be performed on security index
     * @param action request action on security index
     * @return true if action is allowed, false otherwise
     */
    private boolean isActionAllowed(String action) {
        return deniedActionsMatcher.test(action);
    }

    /**
     * Perform access check on requested indices and actions for those indices
     * @param action action to be performed on request indices
     * @param requestedResolved this object contains all indices this request is resolved to
     * @param request the action request to be used for audit logging
     * @param task task in which this access check will be performed
     * @param context conveys information about user and mapped roles, etc.
     * @param actionPrivileges the up-to-date ActionPrivileges instance
     * @param user this user's permissions will be looked up
     */
    private PrivilegesEvaluatorResponse evaluateSystemIndicesAccess(
        final String action,
        final OptionallyResolvedIndices requestedResolved,
        final ActionRequest request,
        final Task task,
        final PrivilegesEvaluationContext context,
        final ActionPrivileges actionPrivileges,
        final User user,
        final boolean containsSystemIndex
    ) {
        boolean serviceAccountUser = user.isServiceAccount();

        if (isSystemIndexPermissionEnabled
            && (!isClusterPermissionStatic(action) || RestoreSnapshotAction.NAME.equals(action))
            && backwartsCompatGateForSystemIndexPrivileges(action, request)) {
            boolean containsRegularIndex = requestedResolved.local().containsAny(index -> !isSystemIndex(index));

            if (serviceAccountUser && containsRegularIndex) {
                auditLog.logSecurityIndexAttempt(request, action, task);
                if (!containsSystemIndex && log.isInfoEnabled()) {
                    log.info("{} not permitted for a service account {} on non-system indices.", action, context.getMappedRoles());
                } else if (containsSystemIndex && log.isDebugEnabled()) {
                    List<String> regularIndices = requestedResolved.local()
                        .names(context.clusterState())
                        .stream()
                        .filter(index -> !isSystemIndex(index))
                        .collect(Collectors.toList());
                    log.debug("Service account cannot access regular indices: {}", regularIndices);
                }
                return PrivilegesEvaluatorResponse.insufficient(action).reason("Service account cannot access regular indices");
            }
            boolean containsProtectedIndex = requestedResolved.local().containsAny(this.securityIndex::equals);
            if (containsProtectedIndex) {
                auditLog.logSecurityIndexAttempt(request, action, task);
                if (log.isInfoEnabled()) {
                    log.info(
                        "{} not permitted for a regular user {} on protected system indices {}",
                        action,
                        context.getMappedRoles(),
                        String.join(", ", this.securityIndex)
                    );
                }
                return PrivilegesEvaluatorResponse.insufficient(action);
            } else if (containsSystemIndex
                && !actionPrivileges.hasExplicitIndexPrivilege(context, SYSTEM_INDEX_PERMISSION_SET, requestedResolved).isAllowed()) {
                    auditLog.logSecurityIndexAttempt(request, action, task);
                    if (log.isInfoEnabled()) {
                        log.info(
                            "No {} permission for user roles {} to System Indices {}",
                            action,
                            context.getMappedRoles(),
                            requestedResolved.local()
                                .names(context.clusterState())
                                .stream()
                                .filter(this::isSystemIndex)
                                .collect(Collectors.joining(", "))
                        );
                    }
                    return PrivilegesEvaluatorResponse.insufficient(action);
                }
        }

        // the following section should only be run for index actions
        if (user.isPluginUser() && !isClusterPermissionStatic(action)) {
            if (this.isSystemIndexEnabled) {
                PluginSystemIndexSelection pluginSystemIndexSelection = areIndicesPluginSystemIndices(
                    context,
                    user.getName().replace("plugin:", ""),
                    requestedResolved
                );
                if (pluginSystemIndexSelection == PluginSystemIndexSelection.CONTAINS_ONLY_PLUGIN_SYSTEM_INDICES) {
                    // plugin is authorized to perform any actions on its own registered system indices
                    return PrivilegesEvaluatorResponse.ok();
                } else if (pluginSystemIndexSelection == PluginSystemIndexSelection.CONTAINS_OTHER_SYSTEM_INDICES) {
                    if (log.isInfoEnabled()) {
                        log.info(
                            "Plugin {} can only perform {} on it's own registered System Indices. Resolved indices: {}",
                            user.getName(),
                            action,
                            requestedResolved
                        );
                    }
                    return PrivilegesEvaluatorResponse.insufficient(action);
                }
            } else {
                // no system index protection and request originating from plugin, allow
                return PrivilegesEvaluatorResponse.ok();
            }
        }

        if (isActionAllowed(action)) {
            if (!(requestedResolved instanceof ResolvedIndices resolvedIndices)) {
                if (filterSecurityIndex) {
                    // TODO
                    // irr.replace(request, false, "*", "-" + securityIndex);
                } else {
                    auditLog.logSecurityIndexAttempt(request, action, task);
                    log.warn("{} for '_all' indices is not allowed for a regular user", action);
                    return PrivilegesEvaluatorResponse.insufficient(action);
                }
            }
            // if system index is enabled and system index permissions are enabled we don't need to perform any further
            // checks as it has already been performed via hasExplicitIndexPermission
            else if (containsSystemIndex && !isSystemIndexPermissionEnabled) {
                if (filterSecurityIndex) {
                    Set<String> allWithoutSecurity = new HashSet<>(requestedResolved.local().names(context.clusterState()));
                    allWithoutSecurity.remove(securityIndex);
                    if (allWithoutSecurity.isEmpty()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Filtered '{}' but resulting list is empty", securityIndex);
                        }
                        return PrivilegesEvaluatorResponse.insufficient(action);
                    }
                    this.indicesRequestModifier.setLocalIndices(request, resolvedIndices, allWithoutSecurity);
                    if (log.isDebugEnabled()) {
                        log.debug("Filtered '{}', resulting list is {}", securityIndex, allWithoutSecurity);
                    }
                } else {
                    auditLog.logSecurityIndexAttempt(request, action, task);
                    final String foundSystemIndexes = requestedResolved.local()
                        .names(context.clusterState())
                        .stream()
                        .filter(this::isSystemIndex)
                        .collect(Collectors.joining(", "));
                    log.warn("{} for '{}' index is not allowed for a regular user", action, foundSystemIndexes);
                    return PrivilegesEvaluatorResponse.insufficient(action);
                }
            }
        }

        return null;
    }

    private PluginSystemIndexSelection areIndicesPluginSystemIndices(
        PrivilegesEvaluationContext context,
        String pluginClassName,
        OptionallyResolvedIndices optionallyResolvedIndices
    ) {
        if (optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices) {
            Predicate<String> pluginSystemIndexPredicate = SystemIndexRegistry.getPluginSystemIndexPredicate(pluginClassName);

            boolean containsNonPluginSystemIndex = false;
            boolean containsOtherSystemIndex = false;

            for (String index : resolvedIndices.local().namesOfIndices(context.clusterState())) {
                if (!pluginSystemIndexPredicate.test(index)) {
                    containsNonPluginSystemIndex = true;
                    if (SystemIndexRegistry.matchesSystemIndexPattern(index)) {
                        containsOtherSystemIndex = true;
                    }
                }
            }

            if (!containsNonPluginSystemIndex) {
                return PluginSystemIndexSelection.CONTAINS_ONLY_PLUGIN_SYSTEM_INDICES;
            } else if (containsOtherSystemIndex) {
                return PluginSystemIndexSelection.CONTAINS_OTHER_SYSTEM_INDICES;
            } else {
                return PluginSystemIndexSelection.NO_SYSTEM_INDICES;
            }
        } else {
            // If we have an unknown state, we must assume that other system indices are contained
            return PluginSystemIndexSelection.CONTAINS_OTHER_SYSTEM_INDICES;
        }
    }

    /**
     * Previous versions of OpenSearch had the bug that indices requests on "*" (or _all) did not get checked
     * in the block of evaluateSystemIndicesAccess() that checks for the explicit system index privileges.
     * This is not nice, but also not a big problem, as write operations would be denied anyway at the end of
     * the evaluateSystemIndicesAccess(). Read operations would be blocked anyway on the Lucene level.
     * With the introduction of the ResolvedIndices object, we do not have a real notion of "is all" any more;
     * thus, this method would now block many requests, even if these would be filtered out later by the DNFOF mode
     * in PrivilegeEvaluator.
     * <p>
     * To keep backwards compatibility, we have this method which disables the first block of evaluateSystemIndicesAccess()
     * for the same cases that were previously skipping its execution. Of course, this is totally hacky, but there
     * is no better way to keep the available functionality other than rewriting the whole logic; which is actually done
     * in the next gen privilege evaluation code.
     * @return true, if the explicit privilege check in evaluateSystemIndicesAccess() shall be executed; false it it shall
     * be skipped.
     */
    private boolean backwartsCompatGateForSystemIndexPrivileges(String action, ActionRequest actionRequest) {
        if (!(actionRequest instanceof IndicesRequest indicesRequest)) {
            // If we cannot resolve indices, we go into the explicit privilege check code; the code will then deny the request
            return true;
        }

        if (deniedActionsMatcher.test(action)) {
            // If this is an action that manipulates documents or indices, we also need to do the explicit privilege check.
            return true;
        }

        String[] indices = indicesRequest.indices();
        boolean isAll = indices == null
            || indices.length == 0
            || (indices.length == 1 && (indices[0] == null || Metadata.ALL.equals(indices[0]) || Regex.isMatchAllPattern(indices[0])));
        if (!isAll) {
            // For non-is-all requests, previous versions also went through the checks
            return true;
        } else {
            // For is-all requests, we can skip the checks; any data in the indices will be filtered out on the Lucene level
            return false;
        }
    }

    enum PluginSystemIndexSelection {
        CONTAINS_ONLY_PLUGIN_SYSTEM_INDICES,
        CONTAINS_OTHER_SYSTEM_INDICES,
        NO_SYSTEM_INDICES
    }
}
