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
package org.opensearch.security.privileges.dlsfls;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.privileges.IndexPattern;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import com.selectivem.collections.CompactMapGroupBuilder;
import com.selectivem.collections.DeduplicatingCompactSubSetBuilder;

/**
 * Abstract super class which provides common DLS/FLS/FM rule evaluation functionality for the concrete classes
 * DocumentPrivileges, FieldPrivileges and FieldMasking.
 * <p>
 * With the exception of the statefulRules property, instances of this class are immutable. The life-cycle of an
 * instance of this class corresponds to the life-cycle of the role configuration. If the role configuration is changed,
 * a new instance needs to be built.
 * <p>
 * Following the secure-by-default principle, this class returns full restrictions if there is no role covering the
 * requested index. It has two fundamental working modes, based on the value of the plugins.security.dfm_empty_overrides_all
 * setting: If the setting is true, roles without a DLS/FLS/FM rule are always considered to grant full access. If the
 * setting is false, roles without a DLS/FLS/FM rule are ONLY considered if there are no other roles that restrict access.
 * The former is the more logical one, as it follows the rule that a user gaining more roles can only gain more privileges.
 * The latter breaks that rule. In that case, a user with more roles can have fewer privileges.
 * <p>
 * Concrete sub-classes of this class must define concrete types for SingleRule and JoinedRule. These should be immutable
 * types. Additionally, they must define a function that converts roles to SingleRule objects and pass that function
 * to the constructor via the roleToRuleFunction parameter. Finally, the abstract methods unrestricted(), restricted()
 * and compile() must be implemented.
 *
 * @param <SingleRule> A single DLS/FLS/FM rule as defined in roles.yml.
 * @param <JoinedRule> A merged DLS/FLS/FM rule that might contain SingleRules from several roles that apply to a user at the same time.
 */
abstract class AbstractRuleBasedPrivileges<SingleRule, JoinedRule extends AbstractRuleBasedPrivileges.Rule> {
    private static final Logger log = LogManager.getLogger(AbstractRuleBasedPrivileges.class);

    /**
     * The roles configuration this instance is based on
     */
    protected final SecurityDynamicConfiguration<RoleV7> roles;

    /**
     * Compiled rules that are immutable.
     */
    protected final StaticRules<SingleRule> staticRules;

    /**
     * Compiled rules, that are denormalized based on the current indices. These are updated whenever the indices change.
     * As this attribute is volatile, access to this attribute should be limited, e.g., not used in tight loops.
     */
    private volatile StatefulRules<SingleRule> statefulRules;

    /**
     * A function that converts role instances to rules.
     */
    private final RoleToRuleFunction<SingleRule> roleToRuleFunction;

    /**
     * Corresponds to the settings flag plugins.security.dfm_empty_overrides_all.
     */
    private final boolean dfmEmptyOverridesAll;

    public AbstractRuleBasedPrivileges(
        SecurityDynamicConfiguration<RoleV7> roles,
        Map<String, IndexAbstraction> indexMetadata,
        RoleToRuleFunction<SingleRule> roleToRuleFunction,
        Settings settings
    ) {
        this.roles = roles;
        this.roleToRuleFunction = roleToRuleFunction;
        this.staticRules = new StaticRules<>(roles, roleToRuleFunction);
        this.dfmEmptyOverridesAll = settings.getAsBoolean(ConfigConstants.SECURITY_DFM_EMPTY_OVERRIDES_ALL, false);
        this.statefulRules = new StatefulRules<>(roles, indexMetadata, roleToRuleFunction);
    }

    /**
     * Returns true if the user identified in the PrivilegesEvaluationContext does not have any restrictions in any case,
     * independently of the indices they are requesting.
     */
    public boolean isUniversallyUnrestricted(PrivilegesEvaluationContext context) {
        if (this.dfmEmptyOverridesAll
            && CollectionUtils.containsAny(this.staticRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())) {
            return true;
        }

        return false;
    }

    /**
     * Returns true if the user identified in the PrivilegesEvaluationContext does not have any restrictions for the
     * given resolved indices.
     *
     * @throws PrivilegesEvaluationException If something went wrong during privileges evaluation. In such cases, any
     *                                       access should be denied to make sure that no unauthorized information is exposed.
     */
    public boolean isUnrestricted(PrivilegesEvaluationContext context, IndexResolverReplacer.Resolved resolved)
        throws PrivilegesEvaluationException {
        if (context.getMappedRoles().isEmpty()) {
            return false;
        }

        if (this.dfmEmptyOverridesAll
            && CollectionUtils.containsAny(this.staticRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())) {
            return true;
        }

        if (resolved == null) {
            return false;
        }

        if (this.hasRestrictedRulesWithIndexWildcard(context)) {
            return false;
        }

        StatefulRules<SingleRule> statefulRules = this.statefulRules;

        // The logic is here a bit tricky: For each index/alias/data stream we assume restrictions until we found an unrestricted role.
        // If we found an unrestricted role, we continue with the next index/alias/data stream. If we found a restricted role, we abort
        // early and return true.

        for (String index : resolved.getAllIndicesResolved(context.getClusterStateSupplier(), context.getIndexNameExpressionResolver())) {
            if (this.dfmEmptyOverridesAll) {
                // We assume that we have a restriction unless there are roles without restriction.
                // Thus, we only have to check the roles without restriction.
                if (!this.hasUnrestrictedRulesExplicit(context, statefulRules, index)) {
                    return false;
                }
            } else {
                // if dfmEmptyOverwritesAll == false, we prefer restricted roles over unrestricted ones.
                // Thus, we first check for restricted roles. Only if there are not any restricted roles,
                // we check for the presence of unrestricted roles. If there are not any matching roles,
                // we also assume full restrictions.

                if (this.hasRestrictedRulesExplicit(context, statefulRules, index)) {
                    return false;
                } else if (!CollectionUtils.containsAny(this.staticRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())
                    && !this.hasUnrestrictedRulesExplicit(context, statefulRules, index)) {
                        return false;
                    }
            }
        }

        return true;
    }

    /**
     * Returns true if there are roles without a rule which imposes restrictions for the particular index.
     * Does consider rules with index wildcards ("*").
     */
    public boolean isUnrestricted(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
        if (context.getMappedRoles().isEmpty()) {
            return false;
        }

        if (this.dfmEmptyOverridesAll
            && CollectionUtils.containsAny(this.staticRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())) {
            return true;
        }

        if (this.hasRestrictedRulesWithIndexWildcard(context)) {
            return false;
        }

        if (this.dfmEmptyOverridesAll) {
            // We assume that we have a restriction unless there are roles without restriction.
            // Thus, we only have to check the roles without restriction.
            return this.hasUnrestrictedRulesExplicit(context, statefulRules, index);
        } else {
            // if dfmEmptyOverwritesAll == false, we prefer restricted roles over unrestricted ones.
            // Thus, we first check for restricted roles. Only if there are not any restricted roles,
            // we check for the presence of unrestricted roles. If there are not any matching roles,
            // we also assume full restrictions.

            if (this.hasRestrictedRulesExplicit(context, statefulRules, index)) {
                return false;
            } else {
                if (CollectionUtils.containsAny(this.staticRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())) {
                    return true;
                }

                return this.hasUnrestrictedRulesExplicit(context, statefulRules, index);
            }
        }
    }

    /**
     * Returns true if there are roles without a rule which imposes restrictions for the particular index.
     * Does not consider rules with index wildcards ("*") - this is reflected by the "explicit" in the method name.
     */
    private boolean hasUnrestrictedRulesExplicit(PrivilegesEvaluationContext context, StatefulRules<SingleRule> statefulRules, String index)
        throws PrivilegesEvaluationException {

        if (statefulRules != null && statefulRules.covers(index)) {
            Set<String> roleWithoutRule = statefulRules.indexToRoleWithoutRule.get(index);

            if (roleWithoutRule != null && CollectionUtils.containsAny(roleWithoutRule, context.getMappedRoles())) {
                return true;
            }
        } else {
            if (this.staticRules.hasUnrestrictedPatterns(context, index)) {
                return true;
            }
        }

        if (this.staticRules.hasUnrestrictedPatternTemplates(context, index)) {
            return true;
        }

        IndexAbstraction indexAbstraction = context.getIndicesLookup().get(index);
        if (indexAbstraction != null) {
            for (String parent : getParents(indexAbstraction)) {
                if (hasUnrestrictedRulesExplicit(context, statefulRules, parent)) {
                    return true;
                }
            }
        }

        return false;

    }

    /**
     * Returns true if there are roles with a rule which imposes restrictions for the particular index.
     * Does not consider rules with index wildcards ("*") - this is reflected by the "explicit" in the method name.
     */
    private boolean hasRestrictedRulesExplicit(PrivilegesEvaluationContext context, StatefulRules<SingleRule> statefulRules, String index)
        throws PrivilegesEvaluationException {

        if (statefulRules != null && statefulRules.covers(index)) {
            Map<String, SingleRule> roleWithRule = statefulRules.indexToRoleToRule.get(index);

            if (roleWithRule != null && CollectionUtils.containsAny(roleWithRule.keySet(), context.getMappedRoles())) {
                return true;
            }
        } else {
            if (this.staticRules.hasRestrictedPatterns(context, index)) {
                return true;
            }
        }

        if (this.staticRules.hasRestrictedPatternTemplates(context, index)) {
            return true;
        }

        IndexAbstraction indexAbstraction = context.getIndicesLookup().get(index);
        if (indexAbstraction != null) {
            for (String parent : getParents(indexAbstraction)) {
                if (hasRestrictedRulesExplicit(context, statefulRules, parent)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns true if the user specified by the given context parameter has roles which apply for the index wildcard ("*")
     * and which specify DLS rules.
     */
    private boolean hasRestrictedRulesWithIndexWildcard(PrivilegesEvaluationContext context) {
        return CollectionUtils.containsAny(this.staticRules.roleWithIndexWildcardToRule.keySet(), context.getMappedRoles());
    }

    /**
     * Returns the joined restrictions for the given index.
     * <p>
     * If you only need to know whether there are restrictions for an index or not, prefer to use isUnrestricted(),
     * as this might be faster.
     *
     * @param context The current PrivilegesEvaluationContext
     * @param index The index to be considered. This can be ONLY a concrete index, not an alias or data stream.
     * @return The joined restrictions for the given index.
     * @throws PrivilegesEvaluationException If something went wrong during privileges evaluation. In such cases, any
     * access should be denied to make sure that no unauthorized information is exposed.
     */
    public JoinedRule getRestriction(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
        return getRestriction(context, index, fullyRestricted());
    }

    /**
     * Returns the joined restrictions for the given index.
     * <p>
     * If you only need to know whether there are restrictions for an index or not, prefer to use isUnrestricted(),
     * as this might be faster.
     *
     * @param context The current PrivilegesEvaluationContext
     * @param index The index to be considered. This can be ONLY a concrete index, not an alias or data stream.
     * @param noRulesDefault Specifies the restriction that shall be used in case no rules are found for an index. Ideally,
     *                       this is fullRestriction(), as the absence of any role mentioning an index means no privileges.
     *                       For backwards compatibility, this might need to be noRestriction().         * @return The joined restrictions for the given index.
     * @throws PrivilegesEvaluationException If something went wrong during privileges evaluation. In such cases, any
     * access should be denied to make sure that no unauthorized information is exposed.
     */
    public JoinedRule getRestriction(PrivilegesEvaluationContext context, String index, JoinedRule noRulesDefault)
        throws PrivilegesEvaluationException {
        if (context.getMappedRoles().isEmpty()) {
            return fullyRestricted();
        }

        if (this.dfmEmptyOverridesAll
            && CollectionUtils.containsAny(this.staticRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())) {
            return unrestricted();
        }

        StatefulRules<SingleRule> statefulRules = this.statefulRules;
        if (statefulRules != null && !statefulRules.covers(index)) {
            statefulRules = null;
        }

        if (this.dfmEmptyOverridesAll && this.hasUnrestrictedRulesExplicit(context, statefulRules, index)) {
            // If dfmEmptyOverwritesAll == true, we can abort early in case unrestricted rules are present. These
            // will overrule any other rules.
            return unrestricted();
        }

        // Collect rules into ruleSink
        Set<SingleRule> ruleSink = new HashSet<>();
        collectRules(context, ruleSink, index, statefulRules);

        IndexAbstraction indexAbstraction = context.getIndicesLookup().get(index);

        if (indexAbstraction != null) {
            for (String parent : getParents(indexAbstraction)) {
                collectRules(context, ruleSink, parent, statefulRules);
            }
        }

        if (ruleSink.isEmpty()) {
            if (this.dfmEmptyOverridesAll) {
                // If we did not find any rules, we assume full restrictions
                return noRulesDefault;
            } else {
                // In case dfmEmptyOverwritesAll == false, we now check for unrestricted rules. If these are present,
                // we give full access. Otherwise, we also assume full restrictions
                if (CollectionUtils.containsAny(this.staticRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())
                    || this.hasUnrestrictedRulesExplicit(context, statefulRules, index)) {
                    return unrestricted();
                } else {
                    return noRulesDefault;
                }
            }
        } else {
            return compile(context, ruleSink);
        }
    }

    /**
     * Returns the joined restrictions for the given indices.
     * <p>
     * If you only need to know whether there are restrictions for an index or not, prefer to use isUnrestricted(),
     * as this might be faster.
     *
     * @param context The current PrivilegesEvaluationContext
     * @param indices The indices to be considered. This can be ONLY concrete indices, not aliases or data streams.
     * @return The joined restrictions for the given indices. The resulting map is guaranteed to contain entries for
     * all indices specified in the corresponding parameter.
     * @throws PrivilegesEvaluationException If something went wrong during privileges evaluation. In such cases, any
     * access should be denied to make sure that no unauthorized information is exposed.
     */
    public IndexToRuleMap<JoinedRule> getRestrictions(PrivilegesEvaluationContext context, Collection<String> indices)
        throws PrivilegesEvaluationException {
        return getRestrictions(context, indices, fullyRestricted());
    }

    /**
     * Returns the joined restrictions for the given indices.
     * <p>
     * If you only need to know whether there are restrictions for an index or not, prefer to use isUnrestricted(),
     * as this might be faster.
     *
     * @param context The current PrivilegesEvaluationContext
     * @param indices The indices to be considered. This can be ONLY concrete indices, not aliases or data streams.y
     * @param noRulesDefault Specifies the restriction that shall be used in case no rules are found for an index. Ideally,
     *                       this is fullRestriction(), as the absence of any role mentioning an index means no privileges.
     *                       For backwards compatibility, this might need to be noRestriction().
     * @return The joined restrictions for the given indices. The resulting map is guaranteed to contain entries for
     * all indices specified in the corresponding parameter.
     * @throws PrivilegesEvaluationException If something went wrong during privileges evaluation. In such cases, any
     * access should be denied to make sure that no unauthorized information is exposed.
     */
    public IndexToRuleMap<JoinedRule> getRestrictions(
        PrivilegesEvaluationContext context,
        Collection<String> indices,
        JoinedRule noRulesDefault
    ) throws PrivilegesEvaluationException {
        if (isUniversallyUnrestricted(context)) {
            return IndexToRuleMap.unrestricted();
        }

        ImmutableMap.Builder<String, JoinedRule> result = ImmutableMap.builderWithExpectedSize(indices.size());

        int restrictedIndices = 0;

        for (String index : indices) {
            JoinedRule restriction = getRestriction(context, index, noRulesDefault);

            if (!restriction.isUnrestricted()) {
                restrictedIndices++;
            }

            result.put(index, restriction);
        }

        if (restrictedIndices == 0) {
            return IndexToRuleMap.unrestricted();
        }

        return new IndexToRuleMap<>(result.build());
    }

    /**
     * Collects the rules for the given index and adds them to the given ruleSink set.
     */
    private void collectRules(
        PrivilegesEvaluationContext context,
        Set<SingleRule> ruleSink,
        String index,
        StatefulRules<SingleRule> statefulRules
    ) throws PrivilegesEvaluationException {
        Map<String, SingleRule> statefulRoleToRule = null;
        boolean statefulRulesEffective;

        if (statefulRules != null) {
            statefulRoleToRule = statefulRules.indexToRoleToRule.get(index);
            statefulRulesEffective = true;
        } else {
            statefulRulesEffective = false;
        }

        for (String role : context.getMappedRoles()) {
            {
                SingleRule rule = this.staticRules.roleWithIndexWildcardToRule.get(role);

                if (rule != null) {
                    ruleSink.add(rule);
                }
            }

            if (statefulRoleToRule != null) {
                SingleRule rule = statefulRoleToRule.get(role);

                if (rule != null) {
                    ruleSink.add(rule);
                }
            }

            if (!statefulRulesEffective) {
                // Only when we have no stateful information, we also check the static index patterns

                Map<WildcardMatcher, SingleRule> indexPatternToRule = this.staticRules.rolesToStaticIndexPatternToRule.get(role);
                if (indexPatternToRule != null) {
                    for (Map.Entry<WildcardMatcher, SingleRule> entry : indexPatternToRule.entrySet()) {
                        WildcardMatcher pattern = entry.getKey();

                        if (pattern.test(index)) {
                            ruleSink.add(entry.getValue());
                        }
                    }
                }
            }

            Map<IndexPattern, SingleRule> dynamicIndexPatternToRule = this.staticRules.rolesToDynamicIndexPatternToRule.get(role);

            if (dynamicIndexPatternToRule != null) {
                for (Map.Entry<IndexPattern, SingleRule> entry : dynamicIndexPatternToRule.entrySet()) {
                    try {
                        if (entry.getKey().matches(index, context, context.getIndicesLookup())) {
                            ruleSink.add(entry.getValue());
                        }
                    } catch (PrivilegesEvaluationException e) {
                        throw new PrivilegesEvaluationException("Error while evaluating index pattern of role " + role, e);
                    }
                }
            }
        }
    }

    /**
     * Returns a rule that signifies full access
     */
    protected abstract JoinedRule unrestricted();

    /**
     * Returns a rule that signifies that a user cannot access anything.
     */
    protected abstract JoinedRule fullyRestricted();

    /**
     * Merges the given collection of single rules into one joined rule.
     */
    protected abstract JoinedRule compile(PrivilegesEvaluationContext context, Collection<SingleRule> rules)
        throws PrivilegesEvaluationException;

    synchronized void updateIndices(Map<String, IndexAbstraction> indexMetadata) {
        StatefulRules<SingleRule> statefulRules = this.statefulRules;

        if (statefulRules == null || !statefulRules.indexMetadata.keySet().equals(indexMetadata.keySet())) {
            this.statefulRules = new StatefulRules<>(roles, indexMetadata, this.roleToRuleFunction);
        }
    }

    /**
     * Returns aliases and/or data streams containing the specified index.
     */
    private Collection<String> getParents(IndexAbstraction indexAbstraction) {
        if (indexAbstraction instanceof IndexAbstraction.Index) {
            IndexAbstraction.Index index = (IndexAbstraction.Index) indexAbstraction;

            if (index.getWriteIndex().getAliases().isEmpty() && index.getParentDataStream() == null) {
                return Collections.emptySet();
            }

            List<String> result = new ArrayList<>(index.getWriteIndex().getAliases().size() + 1);

            for (String aliasName : index.getWriteIndex().getAliases().keySet()) {
                result.add(aliasName);
            }

            if (indexAbstraction.getParentDataStream() != null) {
                result.add(indexAbstraction.getParentDataStream().getName());
            }

            return result;
        } else {
            return Collections.emptySet();
        }
    }

    /**
     * This is an immutable class that contains compiled rules. It is independent of the current indices.
     */
    static class StaticRules<SingleRule> {

        protected final Set<String> rolesWithIndexWildcardWithoutRule;
        protected final Map<String, SingleRule> roleWithIndexWildcardToRule;
        protected final Map<String, Map<IndexPattern, SingleRule>> rolesToDynamicIndexPatternToRule;
        protected final Map<String, Set<IndexPattern>> rolesToDynamicIndexPatternWithoutRule;

        /**
         * Only used when no index metadata is available upon construction
         */
        protected final Map<String, Map<WildcardMatcher, SingleRule>> rolesToStaticIndexPatternToRule;

        /**
         * Only used when no index metadata is available upon construction
         */
        protected final Map<String, WildcardMatcher> rolesToStaticIndexPatternWithoutRule;

        protected final RoleToRuleFunction<SingleRule> roleToRuleFunction;

        StaticRules(SecurityDynamicConfiguration<RoleV7> roles, RoleToRuleFunction<SingleRule> roleToRuleFunction) {
            this.roleToRuleFunction = roleToRuleFunction;

            Set<String> rolesWithIndexWildcardWithoutRule = new HashSet<>();
            Map<String, SingleRule> roleWithIndexWildcardToRule = new HashMap<>();
            Map<String, Map<IndexPattern, SingleRule>> rolesToDynamicIndexPatternToRule = new HashMap<>();
            Map<String, Set<IndexPattern>> rolesToDynamicIndexPatternWithoutRule = new HashMap<>();
            Map<String, Map<WildcardMatcher, SingleRule>> rolesToStaticIndexPatternToRule = new HashMap<>();
            Map<String, List<WildcardMatcher>> rolesToStaticIndexPatternWithoutRule = new HashMap<>();

            for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    for (RoleV7.Index rolePermissions : role.getIndex_permissions()) {
                        if (rolePermissions.getIndex_patterns().contains("*")) {
                            SingleRule singleRule = this.roleToRule(rolePermissions);

                            if (singleRule == null) {
                                rolesWithIndexWildcardWithoutRule.add(roleName);
                            } else {
                                roleWithIndexWildcardToRule.put(roleName, singleRule);
                            }
                        } else {
                            SingleRule singleRule = this.roleToRule(rolePermissions);
                            IndexPattern indexPattern = IndexPattern.from(rolePermissions.getIndex_patterns());

                            if (indexPattern.hasStaticPattern()) {
                                if (singleRule == null) {
                                    rolesToStaticIndexPatternWithoutRule.computeIfAbsent(roleName, k -> new ArrayList<>())
                                        .add(indexPattern.getStaticPattern());
                                } else {
                                    rolesToStaticIndexPatternToRule.computeIfAbsent(roleName, k -> new HashMap<>())
                                        .put(indexPattern.getStaticPattern(), singleRule);
                                }
                            }

                            if (indexPattern.hasDynamicPattern()) {
                                if (singleRule == null) {
                                    rolesToDynamicIndexPatternWithoutRule.computeIfAbsent(roleName, k -> new HashSet<>())
                                        .add(indexPattern.dynamicOnly());
                                } else {
                                    rolesToDynamicIndexPatternToRule.computeIfAbsent(roleName, k -> new HashMap<>())
                                        .put(indexPattern.dynamicOnly(), singleRule);
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    log.error("Unexpected exception while processing role: {}\nIgnoring role.", entry, e);
                }
            }

            this.rolesWithIndexWildcardWithoutRule = rolesWithIndexWildcardWithoutRule;
            this.roleWithIndexWildcardToRule = roleWithIndexWildcardToRule;
            this.rolesToDynamicIndexPatternToRule = rolesToDynamicIndexPatternToRule;
            this.rolesToDynamicIndexPatternWithoutRule = rolesToDynamicIndexPatternWithoutRule;

            this.rolesToStaticIndexPatternToRule = rolesToStaticIndexPatternToRule;
            this.rolesToStaticIndexPatternWithoutRule = rolesToStaticIndexPatternWithoutRule.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(entry -> entry.getKey(), entry -> WildcardMatcher.from(entry.getValue())));
        }

        protected SingleRule roleToRule(RoleV7.Index rolePermissions) throws PrivilegesConfigurationValidationException {
            return this.roleToRuleFunction.apply(rolePermissions);
        }

        /**
         * Only to be used if there is no stateful index information
         */
        boolean hasUnrestrictedPatterns(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
            // We assume that we have a restriction unless there are roles without restriction. This, we only have to check the roles
            // without restriction.
            for (String role : context.getMappedRoles()) {
                WildcardMatcher pattern = this.rolesToStaticIndexPatternWithoutRule.get(role);

                if (pattern != null && pattern.test(index)) {
                    return true;
                }
            }

            // If we found no roles without restriction, we assume a restriction
            return false;
        }

        boolean hasUnrestrictedPatternTemplates(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
            // We assume that we have a restriction unless there are roles without restriction. This, we only have to check the roles
            // without restriction.
            for (String role : context.getMappedRoles()) {
                Set<IndexPattern> dynamicIndexPatternsWithoutRule = this.rolesToDynamicIndexPatternWithoutRule.get(role);

                if (dynamicIndexPatternsWithoutRule != null) {
                    for (IndexPattern indexPatternTemplate : dynamicIndexPatternsWithoutRule) {
                        try {
                            if (indexPatternTemplate.matches(index, context, context.getIndicesLookup())) {
                                return true;
                            }
                        } catch (PrivilegesEvaluationException e) {
                            log.error("Error while matching index pattern of role {}", role, e);
                        }
                    }
                }
            }

            // If we found no roles without restriction, we assume a restriction
            return false;
        }

        /**
         * Only to be used if there is no stateful index information
         */
        boolean hasRestrictedPatterns(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
            for (String role : context.getMappedRoles()) {
                Map<WildcardMatcher, SingleRule> indexPatternToRule = this.rolesToStaticIndexPatternToRule.get(role);

                if (indexPatternToRule != null) {
                    for (WildcardMatcher indexPattern : indexPatternToRule.keySet()) {
                        if (indexPattern.test(index)) {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        boolean hasRestrictedPatternTemplates(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
            for (String role : context.getMappedRoles()) {
                Map<IndexPattern, SingleRule> dynamicIndexPatternToRule = this.rolesToDynamicIndexPatternToRule.get(role);

                if (dynamicIndexPatternToRule != null) {
                    for (IndexPattern indexPattern : dynamicIndexPatternToRule.keySet()) {
                        try {
                            if (indexPattern.matches(index, context, context.getIndicesLookup())) {
                                return true;
                            }
                        } catch (PrivilegesEvaluationException e) {
                            log.error("Error while matching index pattern of role {}", role, e);
                        }
                    }
                }
            }

            return false;
        }
    }

    /**
     * This is an immutable class which contains compiled rules based on the set of actually existing indices. Objects
     * of this class need to be re-constructed whenever the set of indices changes.
     */
    static class StatefulRules<SingleRule> {
        final Map<String, IndexAbstraction> indexMetadata;

        final ImmutableMap<String, Map<String, SingleRule>> indexToRoleToRule;
        final ImmutableMap<String, Set<String>> indexToRoleWithoutRule;

        private final RoleToRuleFunction<SingleRule> roleToRuleFunction;

        StatefulRules(
            SecurityDynamicConfiguration<RoleV7> roles,
            Map<String, IndexAbstraction> indexMetadata,
            RoleToRuleFunction<SingleRule> roleToRuleFunction
        ) {
            this.roleToRuleFunction = roleToRuleFunction;
            this.indexMetadata = indexMetadata;

            DeduplicatingCompactSubSetBuilder<String> roleSetBuilder = new DeduplicatingCompactSubSetBuilder<>(
                roles.getCEntries().keySet()
            );
            CompactMapGroupBuilder<String, SingleRule> roleMapBuilder = new CompactMapGroupBuilder<>(roles.getCEntries().keySet());
            Map<String, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> indexToRoleWithoutRule = new HashMap<>();
            Map<String, CompactMapGroupBuilder.MapBuilder<String, SingleRule>> indexToRoleToRule = new HashMap<>();

            for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    roleSetBuilder.next(roleName);

                    for (RoleV7.Index indexPermissions : role.getIndex_permissions()) {
                        if (indexPermissions.getIndex_patterns().contains("*")) {
                            // Wildcard index patterns are handled in the static IndexPermissions object.
                            continue;
                        }

                        WildcardMatcher indexMatcher = IndexPattern.from(indexPermissions.getIndex_patterns()).getStaticPattern();

                        if (indexMatcher == WildcardMatcher.NONE) {
                            // The pattern is likely blank because there are only dynamic patterns.
                            // Dynamic index patterns are not handled here, but in the static IndexPermissions object
                            continue;
                        }

                        SingleRule rule = this.roleToRule(indexPermissions);

                        if (rule != null) {
                            for (String index : indexMatcher.iterateMatching(indexMetadata.keySet())) {
                                indexToRoleToRule.computeIfAbsent(index, k -> roleMapBuilder.createMapBuilder()).put(roleName, rule);
                            }
                        } else {
                            for (String index : indexMatcher.iterateMatching(indexMetadata.keySet())) {
                                indexToRoleWithoutRule.computeIfAbsent(index, k -> roleSetBuilder.createSubSetBuilder()).add(roleName);
                            }
                        }
                    }
                } catch (Exception e) {
                    log.error("Unexpected exception while processing role: {}\nIgnoring role.", entry, e);
                }
            }

            DeduplicatingCompactSubSetBuilder.Completed<String> completed = roleSetBuilder.build();

            this.indexToRoleToRule = indexToRoleToRule.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(entry -> entry.getKey(), entry -> entry.getValue().build()));
            this.indexToRoleWithoutRule = indexToRoleWithoutRule.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(entry -> entry.getKey(), entry -> entry.getValue().build(completed)));

        }

        protected SingleRule roleToRule(RoleV7.Index rolePermissions) throws PrivilegesConfigurationValidationException {
            return this.roleToRuleFunction.apply(rolePermissions);
        }

        /**
         * Returns true if the given index is known to this instance - then it can be assumed that this instance
         * has proper rules for the index in the indexToRoleToRule and the indexToRoleWithoutRule attributes.
         * <p>
         * If this returns false, this instance cannot be relied on to determine the correct rules.
         */
        boolean covers(String index) {
            return this.indexMetadata.get(index) != null;
        }
    }

    @FunctionalInterface
    static interface RoleToRuleFunction<SingleRule> {
        SingleRule apply(RoleV7.Index indexPrivileges) throws PrivilegesConfigurationValidationException;
    }

    static abstract class Rule {
        abstract boolean isUnrestricted();
    }

}
