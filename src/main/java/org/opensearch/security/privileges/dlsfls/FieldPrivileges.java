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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.PatternSyntaxException;

import com.google.common.collect.ImmutableList;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;

/**
 * This class converts role configuration into pre-computed, optimized data structures for checking FLS privileges.
 * <p>
 * With the exception of the statefulRules property, instances of this class are immutable. The life-cycle of an
 * instance of this class corresponds to the life-cycle of the role configuration. If the role configuration is changed,
 * a new instance needs to be built.
 * <p>
 * Instances of this class are managed by DlsFlsProcessedConfig.
 */
public class FieldPrivileges extends AbstractRuleBasedPrivileges<FieldPrivileges.FlsRule, FieldPrivileges.FlsRule> {
    public FieldPrivileges(SecurityDynamicConfiguration<RoleV7> roles, Map<String, IndexAbstraction> indexMetadata, Settings settings) {
        super(roles, indexMetadata, FieldPrivileges::roleToRule, settings);
    }

    static FlsRule roleToRule(RoleV7.Index rolePermissions) throws PrivilegesConfigurationValidationException {
        List<String> flsPatterns = rolePermissions.getFls();

        if (flsPatterns != null && !flsPatterns.isEmpty()) {
            return FlsRule.from(rolePermissions);
        } else {
            return null;
        }
    }

    @Override
    protected FlsRule unrestricted() {
        return FlsRule.ALLOW_ALL;
    }

    @Override
    protected FlsRule fullyRestricted() {
        return FlsRule.DENY_ALL;
    }

    @Override
    protected FlsRule compile(PrivilegesEvaluationContext context, Collection<FlsRule> rules) throws PrivilegesEvaluationException {
        return FlsRule.merge(rules);
    }

    /**
     * Represents a set of FlsPatterns for a specific index.
     */
    public static class FlsRule extends AbstractRuleBasedPrivileges.Rule {
        static FlsRule of(String... rules) throws PrivilegesConfigurationValidationException {
            return from(FlsPattern.parse(Arrays.asList(rules)), ImmutableList.of());
        }

        static FlsRule from(RoleV7.Index role) throws PrivilegesConfigurationValidationException {
            return from(FlsPattern.parse(role.getFls()), ImmutableList.of(role));
        }

        static FlsRule from(List<FlsPattern> flsPatterns, ImmutableList<RoleV7.Index> sourceRoles)
            throws PrivilegesConfigurationValidationException {
            Set<FlsPattern> flsPatternsIncludingObjectsOnly = new HashSet<>();

            for (FlsPattern flsPattern : flsPatterns) {
                flsPatternsIncludingObjectsOnly.addAll(flsPattern.getParentObjectPatterns());
            }

            // If there are already explicit exclusions on certain object-only inclusions, we can remove these again
            flsPatternsIncludingObjectsOnly.removeAll(flsPatterns);

            return new FlsRule(flsPatterns, flsPatternsIncludingObjectsOnly, sourceRoles);
        }

        static FlsRule merge(Collection<FlsRule> rules) {
            if (rules.size() == 1) {
                return rules.iterator().next();
            }

            Set<FlsPattern> patterns = new HashSet<>();
            Set<FlsPattern> objectOnlyPatterns = new HashSet<>();
            ImmutableList.Builder<RoleV7.Index> roles = ImmutableList.builderWithExpectedSize(rules.size());

            for (FlsRule flsRule : rules) {
                patterns.addAll(flsRule.patterns);
                objectOnlyPatterns.addAll(flsRule.objectOnlyPatterns);
                roles.addAll(flsRule.sourceRole);
            }

            objectOnlyPatterns.removeAll(patterns);

            return new FlsRule(patterns, objectOnlyPatterns, roles.build());
        }

        public static final FlsRule ALLOW_ALL = new FlsRule(ImmutableList.of(), ImmutableList.of(), ImmutableList.of());
        public static final FlsRule DENY_ALL = new FlsRule(
            ImmutableList.of(FlsPattern.EXCLUDE_ALL),
            ImmutableList.of(),
            ImmutableList.of()
        );

        final ImmutableList<RoleV7.Index> sourceRole;
        final ImmutableList<FlsPattern> patterns;
        final ImmutableList<FlsPattern> effectivePatterns;
        final ImmutableList<FlsPattern> objectOnlyPatterns;
        final boolean allowAll;
        final boolean excluding;

        FlsRule(
            Collection<FlsPattern> patterns,
            Collection<FlsPattern> flsPatternsIncludingObjectsOnly,
            ImmutableList<RoleV7.Index> sourceRole
        ) {
            this.sourceRole = sourceRole;

            Set<FlsPattern> flsPatternsExcluding = new HashSet<>(patterns.size());
            Set<FlsPattern> flsPatternsIncluding = new HashSet<>(patterns.size());

            for (FlsPattern flsPattern : patterns) {
                if (flsPattern.isExcluded()) {
                    flsPatternsExcluding.add(flsPattern);
                } else {
                    flsPatternsIncluding.add(flsPattern);
                }
            }

            int exclusions = flsPatternsExcluding.size();
            int inclusions = flsPatternsIncluding.size();

            if (exclusions == 0 && inclusions == 0) {
                // Empty
                this.effectivePatterns = this.patterns = ImmutableList.of(FlsPattern.INCLUDE_ALL);
                this.excluding = false;
                this.allowAll = true;
            } else if (exclusions != 0 && inclusions == 0) {
                // Only exclusions
                this.effectivePatterns = this.patterns = ImmutableList.copyOf(flsPatternsExcluding);
                this.excluding = true;
                this.allowAll = false;
            } else if (exclusions == 0 && inclusions != 0) {
                // Only inclusions
                this.effectivePatterns = this.patterns = ImmutableList.copyOf(flsPatternsIncluding);
                this.excluding = false;
                this.allowAll = flsPatternsIncluding.contains(FlsPattern.INCLUDE_ALL);
            } else {
                // Mixed inclusions and exclusions
                //
                // While the docs say that mixing inclusions and exclusions is not supported, the original
                // implementation only regarded exclusions and disregarded inclusions if these were mixed.
                // We are mirroring this behaviour here. It might make sense to rethink the semantics here,
                // though, as there might be semantics which make more sense. From a UX POV, the current behavior
                // can be quite confusing.
                //
                // See:
                // https://github.com/opensearch-project/security/blob/e73fc24509363cb1573607c6cf47c98780fc89de/src/main/java/org/opensearch/security/configuration/DlsFlsFilterLeafReader.java#L658-L662
                // https://opensearch.org/docs/latest/security/access-control/field-level-security/
                this.patterns = ImmutableList.copyOf(patterns);
                this.effectivePatterns = ImmutableList.copyOf(flsPatternsExcluding);
                this.excluding = true;
                this.allowAll = false;
            }

            this.objectOnlyPatterns = ImmutableList.copyOf(flsPatternsIncludingObjectsOnly);
        }

        public boolean isAllowed(String field) {
            if (isAllowAll()) {
                return true;
            }

            field = stripKeywordSuffix(field);

            if (excluding) {
                for (FlsPattern pattern : this.effectivePatterns) {
                    assert pattern.isExcluded();
                    if (pattern.getPattern().test(field)) {
                        return false;
                    }
                }
                return true;
            } else {
                // including
                for (FlsPattern pattern : this.effectivePatterns) {
                    assert !pattern.isExcluded();
                    if (pattern.getPattern().test(field)) {
                        return true;
                    }
                }
                return false;
            }
        }

        public boolean isObjectAllowed(String field) {
            if (excluding) {
                return isAllowed(field);
            }

            for (FlsPattern pattern : this.objectOnlyPatterns) {
                if (pattern.getPattern().test(field)) {
                    return true;
                }
            }

            return false;
        }

        public boolean isAllowAll() {
            return allowAll;
        }

        @Override
        public String toString() {
            if (isAllowAll()) {
                return "FLS:*";
            } else {
                return "FLS:" + patterns;
            }
        }

        public List<String> getSource() {
            return patterns.stream().map(FlsPattern::getSource).collect(ImmutableList.toImmutableList());
        }

        @Override
        public boolean isUnrestricted() {
            return this.isAllowAll();
        }

        /**
         * See https://github.com/opensearch-project/security/pull/2375
         */
        static String stripKeywordSuffix(String field) {
            if (field.endsWith(".keyword")) {
                return field.substring(0, field.length() - ".keyword".length());
            } else {
                return field;
            }
        }
    }

    /**
     * Represents a single FLS pattern that is matched again a field name.
     * <p>
     * FLS patterns can look like this:
     * <ul>
     *     <li>field - just a simple field name, included in the visible fields
     *     <li>field* - a pattern on a field name, included in the visible fields
     *     <li>~field - a simple field name, excluded from the visible fields (the prefix ! is also supported for legacy reasons, but it is undocumented)
     *     <li>field.field - a field inside another field
     *     <li>Regular expressions enclosed in /.../ (undocumented, does not pair well with nested objects)
     *     <li>Any combination of above
     * </ul>
     */
    public static class FlsPattern {
        public static final FlsPattern INCLUDE_ALL = new FlsPattern(WildcardMatcher.ANY, false, "*");
        public static final FlsPattern EXCLUDE_ALL = new FlsPattern(WildcardMatcher.ANY, true, "~*");

        /**
         * True if the attribute is supposed to be excluded (i.e., pattern started with ~), false otherwise.
         */
        private final boolean excluded;

        /**
         * The compiled pattern (excluding leading ~)
         */
        private final WildcardMatcher pattern;

        /**
         * The original string
         */
        private final String source;

        public FlsPattern(String string) throws PrivilegesConfigurationValidationException {
            try {
                if (string.startsWith("~") || string.startsWith("!")) {
                    excluded = true;
                    pattern = WildcardMatcher.from(string.substring(1));
                } else {
                    pattern = WildcardMatcher.from(string);
                    excluded = false;
                }

                this.source = string;
            } catch (PatternSyntaxException e) {
                throw new PrivilegesConfigurationValidationException("Invalid FLS pattern " + string, e);
            }
        }

        FlsPattern(WildcardMatcher pattern, boolean excluded, String source) {
            this.pattern = pattern;
            this.excluded = excluded;
            this.source = source;
        }

        public String getSource() {
            return source;
        }

        public WildcardMatcher getPattern() {
            return pattern;
        }

        public boolean isExcluded() {
            return excluded;
        }

        @Override
        public String toString() {
            return source;
        }

        List<FlsPattern> getParentObjectPatterns() {
            if (excluded || source.indexOf('.') == -1 || (source.startsWith("/") && source.endsWith("/"))) {
                return Collections.emptyList();
            }

            List<FlsPattern> subPatterns = new ArrayList<>();

            for (int pos = source.indexOf('.'); pos != -1; pos = source.indexOf('.', pos + 1)) {
                String subString = source.substring(0, pos);

                subPatterns.add(new FlsPattern(WildcardMatcher.from(subString), false, subString));
            }

            return subPatterns;
        }

        @Override
        public boolean equals(Object o) {
            if (o instanceof FlsPattern that) {
                return this.source.equals(that.source);
            } else {
                return false;
            }
        }

        @Override
        public int hashCode() {
            return source.hashCode();
        }

        public static List<FlsPattern> parse(List<String> flsPatternStrings) throws PrivilegesConfigurationValidationException {
            List<FlsPattern> flsPatterns = new ArrayList<>(flsPatternStrings.size());

            for (String flsPatternSource : flsPatternStrings) {
                flsPatterns.add(new FlsPattern(flsPatternSource));
            }

            return flsPatterns;
        }

    }

}
