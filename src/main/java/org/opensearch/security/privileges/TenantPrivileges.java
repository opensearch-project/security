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

import java.util.Collection;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.securityconf.impl.v7.TenantV7;
import org.opensearch.security.support.WildcardMatcher;

import com.selectivem.collections.DeduplicatingCompactSubSetBuilder;
import com.selectivem.collections.ImmutableCompactSubSet;

/**
 * Container class for pre-processed tenant privileges. Instances of this class are immutable.
 * New instances are created when the role or when the tenant configuration changes. The creation is managed
 * by the class PrivilegesEvaluator.
 * <p>
 * For tenant privileges that do not use user attributes, this class provides O(1) complexity for tenant privilege
 * evaluation.
 */
public class TenantPrivileges {

    /**
     * Specifies whether an action is just reading data from a tenant or whether it is writing data to a tenant.
     * Used by the hasTenantPrivileges() API.
     */
    public enum ActionType {
        READ,
        WRITE;
    }

    public static final TenantPrivileges EMPTY = new TenantPrivileges(
        SecurityDynamicConfiguration.empty(CType.ROLES),
        SecurityDynamicConfiguration.empty(CType.TENANTS),
        FlattenedActionGroups.EMPTY
    );

    private static final List<ActionType> READ = ImmutableList.of(ActionType.READ);
    private static final List<ActionType> READ_WRITE = ImmutableList.of(ActionType.READ, ActionType.WRITE);

    private static final Logger log = LogManager.getLogger(TenantPrivileges.class);

    /**
     * Stores all names of tenants, as represented in the tenants.yml configuration. This is independent of the role config.
     */
    private final ImmutableSet<String> allTenantNames;

    /**
     * A map from tenant name to ActionType to a set of roles which provide privileges for the respective ActionType.
     * The structure is optimized so that no temporary filtered objects need to be created during privileges evaluation.
     */
    private final ImmutableMap<String, ImmutableMap<ActionType, ImmutableCompactSubSet<String>>> tenantToActionTypeToRoles;

    /**
     * A map from role name to ActionType to strings with dynamic tenant patterns (i.e., tenant patterns that contain
     * user attributes like ${user.name}). This is only used for configurations that use dynamic tenant patterns.
     */
    private final ImmutableMap<String, ImmutableMap<ActionType, ImmutableList<String>>> rolesToActionTypeToDynamicTenantPattern;

    public TenantPrivileges(
        SecurityDynamicConfiguration<RoleV7> roles,
        SecurityDynamicConfiguration<TenantV7> definedTenants,
        FlattenedActionGroups actionGroups
    ) {
        this.allTenantNames = ImmutableSet.copyOf(definedTenants.getCEntries().keySet());

        Map<String, RoleV7> roleEntries = roles.getCEntries();

        DeduplicatingCompactSubSetBuilder<String> roleSetBuilder = new DeduplicatingCompactSubSetBuilder<>(roleEntries.keySet());
        Map<String, Map<ActionType, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>>> tenantToActionTypeToRoles = new HashMap<>();
        Map<String, Map<ActionType, Set<String>>> rolesToActionTypeToDynamicTenantPattern = new HashMap<>();

        for (Map.Entry<String, RoleV7> entry : roleEntries.entrySet()) {
            try {
                String roleName = entry.getKey();
                RoleV7 role = entry.getValue();

                roleSetBuilder.next(roleName);

                for (RoleV7.Tenant tenantPermissions : role.getTenant_permissions()) {
                    List<ActionType> actionTypes = resolveActionType(tenantPermissions.getAllowed_actions(), actionGroups);
                    for (String tenantPattern : tenantPermissions.getTenant_patterns()) {
                        if (UserAttributes.needsAttributeSubstitution(tenantPattern)) {
                            // If a tenant pattern contains a user attribute (like ${user.name}), we can only
                            // do the tenant pattern matching during the actual tenant privilege evaluation, when the user is known.
                            // Thus, we just keep these patterns here unprocessed
                            for (ActionType actionType : actionTypes) {
                                rolesToActionTypeToDynamicTenantPattern.computeIfAbsent(roleName, (k) -> new EnumMap<>(ActionType.class))
                                    .computeIfAbsent(actionType, (k) -> new HashSet<>())
                                    .add(tenantPattern);
                            }
                        } else {
                            // If a tenant pattern contains no user attribute, we can do all the pattern matching on
                            // tenant names in advance
                            for (String tenant : WildcardMatcher.from(tenantPattern).iterateMatching(this.allTenantNames)) {
                                for (ActionType actionType : actionTypes) {
                                    tenantToActionTypeToRoles.computeIfAbsent(tenant, (k) -> new EnumMap<>(ActionType.class))
                                        .computeIfAbsent(actionType, (k) -> roleSetBuilder.createSubSetBuilder())
                                        .add(roleName);
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Unexpected exception while processing role: {}\nIgnoring role.", entry.getKey(), e);
            }
        }

        DeduplicatingCompactSubSetBuilder.Completed<String> completedRoleSetBuilder = roleSetBuilder.build();

        this.tenantToActionTypeToRoles = tenantToActionTypeToRoles.entrySet()
            .stream()
            .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry -> build(entry.getValue(), completedRoleSetBuilder)));

        this.rolesToActionTypeToDynamicTenantPattern = rolesToActionTypeToDynamicTenantPattern.entrySet()
            .stream()
            .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry -> buildDynamicPatternMap(entry.getValue())));
    }

    /**
     * Checks whether the user identified by the given context has privileges to perform actions of the given actionType
     * on the given tenant. Returns true if the user has privileges, false otherwise.
     */
    public boolean hasTenantPrivilege(PrivilegesEvaluationContext context, String tenant, ActionType actionType) {
        // First check the non-dynamic tenant permission configurations; that's the fast path
        Map<ActionType, ImmutableCompactSubSet<String>> actionTypeToRoles = this.tenantToActionTypeToRoles.get(tenant);
        if (actionTypeToRoles != null) {
            ImmutableCompactSubSet<String> roles = actionTypeToRoles.get(actionType);

            if (roles != null && roles.containsAny(context.getMappedRoles())) {
                return true;
            }
        }

        // If we did not find anything with the non-dynamic tenant permission, we will check the dynamic ones
        // First, however, we check if that tenant is valid at all. If not, we abort early.
        if (!this.allTenantNames.contains(tenant)) {
            return false;
        }

        // Now check the dynamic tenant names
        for (String role : context.getMappedRoles()) {
            ImmutableMap<ActionType, ImmutableList<String>> actionTypeToDynamicTenantPattern = this.rolesToActionTypeToDynamicTenantPattern
                .get(role);
            if (actionTypeToDynamicTenantPattern == null) {
                continue;
            }

            ImmutableList<String> dynamicTenantPatterns = actionTypeToDynamicTenantPattern.get(actionType);
            if (dynamicTenantPatterns == null) {
                continue;
            }

            for (String dynamicTenantPattern : dynamicTenantPatterns) {
                try {
                    if (context.getRenderedMatcher(dynamicTenantPattern).test(tenant)) {
                        return true;
                    }
                } catch (Exception e) {
                    log.error(
                        "Error while evaluating dynamic tenant pattern {} of role {}. Ignoring pattern.",
                        dynamicTenantPattern,
                        role,
                        e
                    );
                }
            }
        }

        // The following code block exists only for legacy reasons; it carries over a weird logic from ConfigModelV7:
        // https://github.com/opensearch-project/security/blob/344673a455de956f6a8f3217e61d0636b46a3527/src/main/java/org/opensearch/security/securityconf/ConfigModelV7.java#L230-L232
        // This gives users r/w access to the global tenant if they do not have explicitly configured access to it.
        // As this is surprising and undocumented behavior, it should be removed; possibly, in the next major release
        // of OpenSearch; see https://github.com/opensearch-project/security/issues/5356
        if ("global_tenant".equals(tenant) && context.getMappedRoles().contains("kibana_user")) {
            if (actionTypeToRoles == null) {
                return true;
            }

            ImmutableCompactSubSet<String> readRoles = actionTypeToRoles.get(ActionType.READ);
            if (readRoles == null || !readRoles.containsAny(context.getMappedRoles())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns all tenant names, as configured in the tenants.yml config
     */
    public ImmutableSet<String> allTenantNames() {
        return this.allTenantNames;
    }

    /**
     * Builds an old-style map which lists all tenants a user has access to and sets the value to
     * true if the user has read/write access. If a user has read only access, the value will be false.
     * <p>
     * Note: This only exists to provide backwards compatibility; the way the information is presented
     * here is less than optimal, as it is not self-explanatory.
     */
    public Map<String, Boolean> tenantMap(PrivilegesEvaluationContext context) {
        HashMap<String, Boolean> result = new HashMap<>();

        for (String tenant : this.allTenantNames) {
            if (hasTenantPrivilege(context, tenant, ActionType.WRITE)) {
                result.put(tenant, true);
            } else if (hasTenantPrivilege(context, tenant, ActionType.READ)) {
                result.put(tenant, false);
            }
        }

        // Additionally, the private tenant is represented in the result map as the user's name.
        // This is also not ideal, but this is also for backwards compatibility.
        result.put(context.getUser().getName(), true);

        return result;
    }

    static List<ActionType> resolveActionType(Collection<String> allowedActions, FlattenedActionGroups actionGroups) {
        ImmutableSet<String> permissions = actionGroups.resolve(allowedActions);
        if (permissions.contains("kibana:saved_objects/*/write")) {
            return READ_WRITE;
        } else {
            return READ;
        }
    }

    private static ImmutableMap<ActionType, ImmutableCompactSubSet<String>> build(
        Map<ActionType, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> source,
        DeduplicatingCompactSubSetBuilder.Completed<String> completedRoleSetBuilder
    ) {
        EnumMap<ActionType, ImmutableCompactSubSet<String>> result = new EnumMap<>(ActionType.class);

        for (Map.Entry<ActionType, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> sourceEntry : source.entrySet()) {
            result.put(sourceEntry.getKey(), sourceEntry.getValue().build(completedRoleSetBuilder));
        }

        return ImmutableMap.copyOf(result);
    }

    private static ImmutableMap<ActionType, ImmutableList<String>> buildDynamicPatternMap(Map<ActionType, Set<String>> source) {
        EnumMap<ActionType, ImmutableList<String>> result = new EnumMap<>(ActionType.class);

        for (Map.Entry<ActionType, Set<String>> sourceEntry : source.entrySet()) {
            result.put(sourceEntry.getKey(), ImmutableList.copyOf(sourceEntry.getValue()));
        }

        return ImmutableMap.copyOf(result);
    }
}
