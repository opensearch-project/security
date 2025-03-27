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

package org.opensearch.security.configuration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.threadpool.ThreadPool;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

public class SettingsPermissionValveImpl implements SettingsPermissionValve {
    private static final Logger log = LogManager.getLogger(SettingsPermissionValveImpl.class);

    private final AtomicReference<SecurityDynamicConfiguration<RoleV7>> rolesConfiguration = new AtomicReference<>();
    private final ClusterService clusterService;
    private final AdminDNs adminDNs;
    private final AuditLog auditLog;

    public SettingsPermissionValveImpl(
        ClusterService clusterService,
        AdminDNs adminDNs,
        AuditLog auditLog
    ) {
        this.clusterService = clusterService;
        this.adminDNs = adminDNs;
        this.auditLog = auditLog;

        // Add listener for configuration updates
        clusterService.addListener(event -> {
            SecurityDynamicConfiguration<RoleV7> config = rolesConfiguration.get();
            if (config != null) {
                // Handle any cluster state related updates if needed
            }
        });
    }

    @Override
    public boolean invoke(PrivilegesEvaluationContext context, ActionListener<?> listener) {
        final ActionRequest request = context.getRequest();
        
        // Skip validation for admin users
        if (adminDNs.isAdmin(context.getUser())) {
            return true;
        }

        try {
            if (request instanceof ClusterUpdateSettingsRequest) {
                return validateClusterSettings(context, (ClusterUpdateSettingsRequest) request, listener);
            } else if (request instanceof UpdateSettingsRequest) {
                return validateIndexSettings(context, (UpdateSettingsRequest) request, listener);
            }
            return true;
        } catch (Exception e) {
            log.error("Error while evaluating settings permissions", e);
            listener.onFailure(new SecurityException("Error while evaluating settings permissions: " + e.getMessage()));
            return false;
        }
    }

    private boolean validateClusterSettings(
        PrivilegesEvaluationContext context,
        ClusterUpdateSettingsRequest request,
        ActionListener<?> listener
    ) {
        // Get allowed settings patterns from user's roles
        Set<String> allowedSettings = getAllowedSettingsFromRoles(context);

        // For backwards compatibility we will allow all settings if no allowed settings are defined
        if (allowedSettings.isEmpty()) {
            return true;
        }
        log.debug("Allowed settings: {} for user: {}", allowedSettings, context.getUser().getName());

        // Validate persistent settings
        if (!validateSettingsMap(request.persistentSettings(), allowedSettings)) {
            auditLog.logMissingPrivileges(context.getAction(), request, context.getTask());
            listener.onFailure(
                new OpenSearchSecurityException("User not authorized to modify these cluster settings: " + request.persistentSettings().keySet(), RestStatus.FORBIDDEN)
            );
            return false;
        }

        // Validate transient settings
        if (!validateSettingsMap(request.transientSettings(), allowedSettings)) {
            auditLog.logMissingPrivileges(context.getAction(), request, context.getTask());
            listener.onFailure(
                new OpenSearchSecurityException("User not authorized to modify these cluster settings: " + request.transientSettings().keySet(), RestStatus.FORBIDDEN)
            );
            return false;
        }

        return true;
    }

    private boolean validateIndexSettings(
        PrivilegesEvaluationContext context,
        UpdateSettingsRequest request,
        ActionListener<?> listener
    ) {
        // Get allowed settings patterns from user's roles
        Set<String> allowedSettings = getAllowedSettingsFromRoles(context);

        if (!validateSettingsMap(request.settings(), allowedSettings)) {
            auditLog.logMissingPrivileges(context.getAction(), request, context.getTask());
            listener.onFailure(
                new SecurityException("User not authorized to modify these index settings: " + request.settings().keySet())
            );
            return false;
        }

        return true;
    }

    private Set<String> getAllowedSettingsFromRoles(PrivilegesEvaluationContext context) {
        Set<String> allowedSettings = new HashSet<>();
        SecurityDynamicConfiguration<RoleV7> roles = rolesConfiguration.get();

        if (roles != null && roles.getCEntries() != null) {
            for (String role : context.getUser().getRoles()) {
                RoleV7 roleConfig = roles.getCEntries().get(role);
                if (roleConfig != null) {
                    // Get cluster-level settings permissions
                    Set<String> clusterSettings = roleConfig.getAllowed_cluster_settings();
                    if (clusterSettings != null) {
                        allowedSettings.addAll(clusterSettings);
                    }

                    // Get index-level settings from index permissions
                    List<RoleV7.Index> indexPermissions = roleConfig.getIndex_permissions();
                    if (indexPermissions != null) {
                        for (RoleV7.Index indexPermission : indexPermissions) {
                            Set<String> indexSettings = indexPermission.getAllowed_settings();
                            if (indexSettings != null) {
                                allowedSettings.addAll(indexSettings);
                            }
                        }
                    }
                }
            }
        }
        
        return allowedSettings;
    }

    private boolean validateSettingsMap(Settings settingsToValidate, Set<String> allowedPatterns) {
        if (settingsToValidate.isEmpty() || allowedPatterns.isEmpty()) {
            return true;
        }

        for (String key : settingsToValidate.keySet()) {
            boolean matched = false;
            for (String pattern : allowedPatterns) {
                if (WildcardMatcher.from(pattern).test(key)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                log.debug("Setting {} not allowed for current user", key);
                return false;
            }
        }
        return true;
    }

    public void updateConfiguration(SecurityDynamicConfiguration<RoleV7> rolesConfig) {
        if (rolesConfig != null) {
            rolesConfiguration.set(rolesConfig.clone());
        }
    }
}
