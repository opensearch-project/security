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

package org.opensearch.security.privileges;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.RealtimeRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.securityconf.IndexPattern;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.tasks.Task;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class performs authorization on requests targeting system indices
 * NOTE:
 * - The term `protected system indices` used here translates to system indices
 *   which have an added layer of security and cannot be accessed by anyone except Super Admin
 */
public class SecurityIndexAccessEvaluator {

    Logger log = LogManager.getLogger(this.getClass());

    private final String securityIndex;
    private final AuditLog auditLog;
    private final IndexResolverReplacer irr;
    private final boolean filterSecurityIndex;
    // for system-indices configuration
    private final WildcardMatcher systemIndexMatcher;
    private final WildcardMatcher protectedSystemIndexMatcher;
    private final WildcardMatcher deniedActionsMatcher;

    private final boolean isSystemIndexEnabled;
    private final boolean isSystemIndexPermissionEnabled;

    public SecurityIndexAccessEvaluator(final Settings settings, AuditLog auditLog, IndexResolverReplacer irr) {
        this.securityIndex = settings.get(
            ConfigConstants.SECURITY_CONFIG_INDEX_NAME,
            ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX
        );
        this.auditLog = auditLog;
        this.irr = irr;
        this.filterSecurityIndex = settings.getAsBoolean(ConfigConstants.SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS, false);
        this.systemIndexMatcher = WildcardMatcher.from(
            settings.getAsList(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, ConfigConstants.SECURITY_SYSTEM_INDICES_DEFAULT)
        );
        this.protectedSystemIndexMatcher = WildcardMatcher.from(ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.isSystemIndexEnabled = settings.getAsBoolean(
            ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY,
            ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_DEFAULT
        );
        final boolean restoreSecurityIndexEnabled = settings.getAsBoolean(
            ConfigConstants.SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED,
            false
        );

        final List<String> securityIndexDeniedActionPatternsList = deniedActionPatterns();

        final List<String> securityIndexDeniedActionPatternsListNoSnapshot = new ArrayList<>(securityIndexDeniedActionPatternsList);
        securityIndexDeniedActionPatternsListNoSnapshot.add("indices:admin/close*");
        securityIndexDeniedActionPatternsListNoSnapshot.add("cluster:admin/snapshot/restore*");

        deniedActionsMatcher = WildcardMatcher.from(
            restoreSecurityIndexEnabled ? securityIndexDeniedActionPatternsList : securityIndexDeniedActionPatternsListNoSnapshot
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
        final Resolved requestedResolved,
        final PrivilegesEvaluatorResponse presponse,
        final SecurityRoles securityRoles
    ) {
        final boolean isDebugEnabled = log.isDebugEnabled();

        evaluateSystemIndicesAccess(action, requestedResolved, request, task, presponse, isDebugEnabled, securityRoles);

        if (requestedResolved.isLocalAll()
            || requestedResolved.getAllIndices().contains(securityIndex)
            || requestContainsAnySystemIndices(requestedResolved)) {

            if (request instanceof SearchRequest) {
                ((SearchRequest) request).requestCache(Boolean.FALSE);
                if (isDebugEnabled) {
                    log.debug("Disable search request cache for this request");
                }
            }

            if (request instanceof RealtimeRequest) {
                ((RealtimeRequest) request).realtime(Boolean.FALSE);
                if (isDebugEnabled) {
                    log.debug("Disable realtime for this request");
                }
            }
        }
        return presponse;
    }

    /**
     * Checks whether user has `system:admin/system_index` explicitly specified
     * as an allowed action under any of its mapped roles
     * @param securityRoles roles in which the permission needs to be checked
     * @return true if user does not have permission, false otherwise
     */
    private boolean isSystemIndexAccessProhibitedForUser(SecurityRoles securityRoles) {
        // Excluding `*` allowed action as it shouldn't grant system index privilege
        Set<WildcardMatcher> userPermissions = securityRoles.getRoles()
            .stream()
            .flatMap(role -> role.getIpatterns().stream())
            .map(IndexPattern::getNonWildCardPerms)
            .collect(Collectors.toSet());

        for (WildcardMatcher userPermission : userPermissions) {
            if (userPermission.matchAny(ConfigConstants.SYSTEM_INDEX_PERMISSION)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if request is for any system index
     * @param requestedResolved request which contains indices to be matched against system indices
     * @return true if a match is found, false otherwise
     */
    private boolean requestContainsAnySystemIndices(final Resolved requestedResolved) {
        return !getAllSystemIndices(requestedResolved).isEmpty();
    }

    /**
     * Gets all indices requested in the original request.
     * It will always return security index if it is present in the request, as security index is protected regardless
     * of feature being enabled or disabled
     * @param requestedResolved request which contains indices to be matched against system indices
     * @return the list of protected system indices present in the request
     */
    private List<String> getAllSystemIndices(final Resolved requestedResolved) {
        final List<String> systemIndices = requestedResolved.getAllIndices()
            .stream()
            .filter(securityIndex::equals)
            .collect(Collectors.toList());
        if (isSystemIndexEnabled) {
            systemIndices.addAll(systemIndexMatcher.getMatchAny(requestedResolved.getAllIndices(), Collectors.toList()));
        }
        return systemIndices;
    }

    /**
     * Checks if request contains any system index that is non-permission-able
     * NOTE: Security index is currently non-permission-able
     * @param requestedResolved request which contains indices to be matched against non-permission-able system indices
     * @return true if the request contains any non-permission-able index,false otherwise
     */
    private boolean requestContainsAnyProtectedSystemIndices(final Resolved requestedResolved) {
        return !getAllProtectedSystemIndices(requestedResolved).isEmpty();
    }

    /**
     * Filters the request to get all system indices that are protected and are non-permission-able
     * @param requestedResolved request which contains indices to be matched against non-permission-able system indices
     * @return the list of protected system indices present in the request
     */
    private List<String> getAllProtectedSystemIndices(final Resolved requestedResolved) {
        return new ArrayList<>(protectedSystemIndexMatcher.getMatchAny(requestedResolved.getAllIndices(), Collectors.toList()));
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
     * @param presponse the pre-response object that will eventually become a response and returned to the requester
     * @param isDebugEnabled flag to indicate whether debug logging is enabled
     * @param securityRoles user's roles which will be used for access evaluation
     */
    private void evaluateSystemIndicesAccess(
        String action,
        Resolved requestedResolved,
        ActionRequest request,
        Task task,
        PrivilegesEvaluatorResponse presponse,
        Boolean isDebugEnabled,
        SecurityRoles securityRoles
    ) {
        // Perform access check is system index permissions are enabled
        boolean containsSystemIndex = requestContainsAnySystemIndices(requestedResolved);

        if (isSystemIndexPermissionEnabled) {
            boolean containsProtectedIndex = requestContainsAnyProtectedSystemIndices(requestedResolved);
            if (containsProtectedIndex) {
                auditLog.logSecurityIndexAttempt(request, action, task);
                if (log.isInfoEnabled()) {
                    log.info(
                        "{} not permitted for a regular user {} on protected system indices {}",
                        action,
                        securityRoles,
                        String.join(", ", getAllProtectedSystemIndices(requestedResolved))
                    );
                }
                presponse.allowed = false;
                presponse.markComplete();
                return;
            } else if (containsSystemIndex && isSystemIndexAccessProhibitedForUser(securityRoles)) {
                auditLog.logSecurityIndexAttempt(request, action, task);
                if (log.isInfoEnabled()) {
                    log.info(
                        "No {} permission for user roles {} to System Indices {}",
                        action,
                        securityRoles,
                        String.join(", ", getAllSystemIndices(requestedResolved))
                    );
                }
                presponse.allowed = false;
                presponse.markComplete();
                return;
            }
        }

        if (isActionAllowed(action)) {
            if (requestedResolved.isLocalAll()) {
                if (filterSecurityIndex) {
                    irr.replace(request, false, "*", "-" + securityIndex);
                    if (isDebugEnabled) {
                        log.debug(
                            "Filtered '{}' from {}, resulting list with *,-{} is {}",
                            securityIndex,
                            requestedResolved,
                            securityIndex,
                            irr.resolveRequest(request)
                        );
                    }
                } else {
                    auditLog.logSecurityIndexAttempt(request, action, task);
                    log.warn("{} for '_all' indices is not allowed for a regular user", action);
                    presponse.allowed = false;
                    presponse.markComplete();
                }
            } else if (containsSystemIndex && !isSystemIndexPermissionEnabled) {
                // if system index is enabled and system index permissions are enabled we don't need to perform any further
                // checks as it has already been performed via isSystemIndexAccessProhibitedForUser

                if (filterSecurityIndex) {
                    Set<String> allWithoutSecurity = new HashSet<>(requestedResolved.getAllIndices());
                    allWithoutSecurity.remove(securityIndex);
                    if (allWithoutSecurity.isEmpty()) {
                        if (isDebugEnabled) {
                            log.debug("Filtered '{}' but resulting list is empty", securityIndex);
                        }
                        presponse.allowed = false;
                        presponse.markComplete();
                        return;
                    }
                    irr.replace(request, false, allWithoutSecurity.toArray(new String[0]));
                    if (isDebugEnabled) {
                        log.debug("Filtered '{}', resulting list is {}", securityIndex, allWithoutSecurity);
                    }
                } else {
                    auditLog.logSecurityIndexAttempt(request, action, task);
                    final String foundSystemIndexes = String.join(", ", getAllSystemIndices(requestedResolved));
                    log.warn("{} for '{}' index is not allowed for a regular user", action, foundSystemIndexes);
                    presponse.allowed = false;
                    presponse.markComplete();
                }
            }
        }
    }
}
