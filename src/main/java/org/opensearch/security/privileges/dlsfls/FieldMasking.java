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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import org.apache.commons.lang3.StringUtils;
import org.apache.lucene.util.BytesRef;
import org.bouncycastle.util.encoders.Hex;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.Salt;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import com.rfksystems.blake2b.Blake2b;

/**
 * This class converts role configuration into pre-computed, optimized data structures for applying field masking
 * to indexed documents.
 * <p>
 * With the exception of the statefulRules property, instances of this class are immutable. The life-cycle of an
 * instance of this class corresponds to the life-cycle of the role configuration. If the role configuration is changed,
 * a new instance needs to be built.
 * <p>
 * Instances of this class are managed by DlsFlsProcessedConfig.
 */
public class FieldMasking extends AbstractRuleBasedPrivileges<FieldMasking.FieldMaskingRule.SimpleRule, FieldMasking.FieldMaskingRule> {

    private final FieldMasking.Config fieldMaskingConfig;

    public FieldMasking(
        SecurityDynamicConfiguration<RoleV7> roles,
        Map<String, IndexAbstraction> indexMetadata,
        FieldMasking.Config fieldMaskingConfig,
        Settings settings
    ) {
        super(roles, indexMetadata, (rolePermissions) -> roleToRule(rolePermissions, fieldMaskingConfig), settings);
        this.fieldMaskingConfig = fieldMaskingConfig;
    }

    static FieldMaskingRule.SimpleRule roleToRule(RoleV7.Index rolePermissions, FieldMasking.Config fieldMaskingConfig)
        throws PrivilegesConfigurationValidationException {
        List<String> fmExpressions = rolePermissions.getMasked_fields();

        if (fmExpressions != null && !fmExpressions.isEmpty()) {
            return new FieldMaskingRule.SimpleRule(rolePermissions, fieldMaskingConfig);
        } else {
            return null;
        }
    }

    @Override
    protected FieldMaskingRule unrestricted() {
        return FieldMaskingRule.ALLOW_ALL;
    }

    @Override
    protected FieldMaskingRule fullyRestricted() {
        return new FieldMaskingRule.SimpleRule(
            ImmutableList.of(new FieldMaskingRule.Field(FieldMaskingExpression.MASK_ALL, fieldMaskingConfig))
        );
    }

    @Override
    protected FieldMaskingRule compile(PrivilegesEvaluationContext context, Collection<FieldMaskingRule.SimpleRule> rules)
        throws PrivilegesEvaluationException {
        return new FieldMaskingRule.MultiRole(rules);
    }

    public static abstract class FieldMaskingRule extends AbstractRuleBasedPrivileges.Rule {
        public static final FieldMaskingRule ALLOW_ALL = new SimpleRule(ImmutableList.of());

        public static FieldMaskingRule of(FieldMasking.Config fieldMaskingConfig, String... rules)
            throws PrivilegesConfigurationValidationException {
            ImmutableList.Builder<Field> patterns = new ImmutableList.Builder<>();

            for (String rule : rules) {
                patterns.add(new Field(new FieldMaskingExpression(rule), fieldMaskingConfig));
            }

            return new SimpleRule(patterns.build());
        }

        public abstract Field get(String field);

        public abstract boolean isAllowAll();

        public boolean isMasked(String field) {
            return get(field) != null;
        }

        public boolean isUnrestricted() {
            return this.isAllowAll();
        }

        public abstract List<String> getSource();

        /**
         * A rule which was derived directly from exactly one role.
         */
        public static class SimpleRule extends FieldMaskingRule {

            final RoleV7.Index sourceIndex;
            final ImmutableList<FieldMaskingRule.Field> expressions;

            SimpleRule(RoleV7.Index sourceIndex, FieldMasking.Config fieldMaskingConfig) throws PrivilegesConfigurationValidationException {
                this.sourceIndex = sourceIndex;
                this.expressions = parseExpressions(sourceIndex, fieldMaskingConfig);
            }

            SimpleRule(ImmutableList<Field> expressions) {
                this.sourceIndex = null;
                this.expressions = expressions;
            }

            public Field get(String field) {
                return internalGet(stripKeywordSuffix(field));
            }

            private Field internalGet(String field) {
                for (Field expression : this.expressions) {
                    if (expression.getPattern().test(field)) {
                        return expression;
                    }
                }

                return null;
            }

            public boolean isAllowAll() {
                return expressions.isEmpty();
            }

            @Override
            public String toString() {
                if (isAllowAll()) {
                    return "FM:[]";
                } else {
                    return "FM:" + expressions;
                }
            }

            @Override
            public List<String> getSource() {
                return this.expressions.stream().map(FieldMaskingRule.Field::getSource).collect(Collectors.toList());
            }

            static ImmutableList<FieldMaskingRule.Field> parseExpressions(RoleV7.Index index, FieldMasking.Config fieldMaskingConfig)
                throws PrivilegesConfigurationValidationException {
                ImmutableList.Builder<FieldMaskingRule.Field> result = ImmutableList.builder();

                for (String source : index.getMasked_fields()) {
                    result.add(new Field(new FieldMaskingExpression(source), fieldMaskingConfig));
                }

                return result.build();
            }
        }

        public static class MultiRole extends FieldMaskingRule {
            final ImmutableList<SimpleRule> parts;
            final boolean allowAll;

            MultiRole(Collection<SimpleRule> parts) {
                this.parts = ImmutableList.copyOf(parts);
                this.allowAll = this.parts.stream().anyMatch(SimpleRule::isAllowAll);
            }

            public Field get(String field) {
                field = stripKeywordSuffix(field);

                for (SimpleRule part : parts) {
                    Field masking = part.get(field);

                    if (masking != null) {
                        return masking;
                    }
                }

                return null;
            }

            public boolean isAllowAll() {
                return allowAll;
            }

            @Override
            public String toString() {
                if (isAllowAll()) {
                    return "FM:[]";
                } else {
                    return "FM:" + parts.stream().map((p) -> p.expressions).collect(Collectors.toList());
                }
            }

            @Override
            public List<String> getSource() {
                return this.parts.stream().flatMap(r -> r.getSource().stream()).collect(Collectors.toList());
            }
        }

        /**
         * Represents a single field that is supposed to be masked. Combines a single expression with the global
         * configuration.
         */
        public static class Field {
            private final FieldMaskingExpression expression;

            private final String hashAlgorithm;
            private final Salt salt;
            private final byte[] saltBytes;

            Field(FieldMaskingExpression expression, FieldMasking.Config fieldMaskingConfig) {
                this.expression = expression;
                this.hashAlgorithm = expression.getAlgoName() != null ? expression.getAlgoName()
                    : StringUtils.isNotEmpty(fieldMaskingConfig.getDefaultHashAlgorithm()) ? fieldMaskingConfig.getDefaultHashAlgorithm()
                    : null;
                this.salt = fieldMaskingConfig.getSalt();
                this.saltBytes = this.salt.getSalt16();
            }

            public WildcardMatcher getPattern() {
                return expression.getPattern();
            }

            public byte[] apply(byte[] value) {
                if (expression.getRegexReplacements() != null) {
                    return applyRegexReplacements(value, expression.getRegexReplacements());
                } else if (this.hashAlgorithm != null) {
                    return customHash(value, this.hashAlgorithm);
                } else {
                    return blake2bHash(value);
                }
            }

            public String apply(String value) {
                return new String(apply(value.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
            }

            public BytesRef apply(BytesRef value) {
                if (value == null) {
                    return null;
                }

                return new BytesRef(apply(BytesRef.deepCopyOf(value).bytes));
            }

            @Override
            public String toString() {
                return expression.toString();
            }

            String getSource() {
                return expression.getSource();
            }

            FieldMaskingExpression getExpression() {
                return expression;
            }

            private static byte[] customHash(byte[] in, String algorithm) {
                try {
                    MessageDigest digest = MessageDigest.getInstance(algorithm);
                    return Hex.encode(digest.digest(in));
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalArgumentException(e);
                }
            }

            private byte[] applyRegexReplacements(byte[] value, List<FieldMaskingExpression.RegexReplacement> regexReplacements) {
                String string = new String(value, StandardCharsets.UTF_8);
                for (FieldMaskingExpression.RegexReplacement rr : regexReplacements) {
                    string = rr.getRegex().matcher(string).replaceAll(rr.getReplacement());
                }
                return string.getBytes(StandardCharsets.UTF_8);
            }

            private byte[] blake2bHash(byte[] in) {
                // Salt is passed incorrectly but order of parameters is retained at present to ensure full backwards compatibility
                // Tracking with https://github.com/opensearch-project/security/issues/4274
                final Blake2b hash = new Blake2b(null, 32, null, saltBytes);
                hash.update(in, 0, in.length);
                final byte[] out = new byte[hash.getDigestSize()];
                hash.digest(out, 0);

                return Hex.encode(out);
            }
        }

        static String stripKeywordSuffix(String field) {
            if (field.endsWith(".keyword")) {
                return field.substring(0, field.length() - ".keyword".length());
            } else {
                return field;
            }
        }
    }

    /**
     * Represents a parsed field masking expression from the roles.yml file.
     */
    public static class FieldMaskingExpression {
        public static final FieldMaskingExpression MASK_ALL = new FieldMaskingExpression(WildcardMatcher.ANY, "*");

        private final WildcardMatcher pattern;
        private final String algoName;
        private final List<RegexReplacement> regexReplacements;
        private final String source;

        public FieldMaskingExpression(String value) throws PrivilegesConfigurationValidationException {
            this.source = value;

            List<String> tokens = Splitter.on("::").splitToList(value);
            pattern = WildcardMatcher.from(tokens.get(0));

            if (tokens.size() == 1) {
                algoName = null;
                regexReplacements = null;
            } else if (tokens.size() == 2) {
                regexReplacements = null;
                try {
                    this.algoName = tokens.get(1);
                    // We try to instantiate the MessageDigest instance already now to make sure that it is valid.
                    // However, we do not store the instance as MessageDigest instance are NOT thread safe.
                    // Some MessageDigest implementations allow to be cloned. A possible future optimization would
                    // be detecting whether the instances can be cloned and then using the clone method for
                    // construction.
                    MessageDigest.getInstance(tokens.get(1));
                } catch (NoSuchAlgorithmException e) {
                    throw new PrivilegesConfigurationValidationException("Invalid algorithm " + tokens.get(1));
                }
            } else if (tokens.size() % 2 == 1) {
                algoName = null;
                regexReplacements = new ArrayList<>((tokens.size() - 1) / 2);
                for (int i = 1; i < tokens.size() - 1; i = i + 2) {
                    regexReplacements.add(new RegexReplacement(tokens.get(i), tokens.get(i + 1)));
                }
            } else {
                throw new PrivilegesConfigurationValidationException(
                    "A field masking expression must have the form 'field_name', 'field_name::algorithm', 'field_name::regex::replacement' or 'field_name::(regex::replacement)+'"
                );
            }
        }

        private FieldMaskingExpression(WildcardMatcher pattern, String source) {
            this.pattern = pattern;
            this.source = source;
            this.algoName = null;
            this.regexReplacements = null;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof FieldMaskingExpression)) {
                return false;
            }
            FieldMaskingExpression that = (FieldMaskingExpression) o;
            return Objects.equals(pattern, that.pattern)
                && Objects.equals(algoName, that.algoName)
                && Objects.equals(regexReplacements, that.regexReplacements);
        }

        @Override
        public int hashCode() {
            return Objects.hash(pattern, algoName, regexReplacements);
        }

        static class RegexReplacement {
            private final java.util.regex.Pattern regex;
            private final String replacement;

            RegexReplacement(String regex, String replacement) throws PrivilegesConfigurationValidationException {
                if (!regex.startsWith("/") || !regex.endsWith("/")) {
                    throw new PrivilegesConfigurationValidationException("A regular expression needs to be wrapped in /.../");
                }

                try {
                    this.regex = java.util.regex.Pattern.compile(regex.substring(1).substring(0, regex.length() - 2));
                } catch (PatternSyntaxException e) {
                    throw new PrivilegesConfigurationValidationException(e.getMessage(), e);
                }

                this.replacement = replacement;
            }

            java.util.regex.Pattern getRegex() {
                return regex;
            }

            String getReplacement() {
                return replacement;
            }

            @Override
            public String toString() {
                return "/" + regex + "/::" + replacement;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof RegexReplacement that)) return false;
                return Objects.equals(regex.pattern(), that.regex.pattern()) && Objects.equals(replacement, that.replacement);
            }

            @Override
            public int hashCode() {
                return Objects.hash(regex.pattern(), replacement);
            }
        }

        @Override
        public String toString() {
            return source;
        }

        String getAlgoName() {
            return algoName;
        }

        List<RegexReplacement> getRegexReplacements() {
            return regexReplacements;
        }

        WildcardMatcher getPattern() {
            return pattern;
        }

        String getSource() {
            return source;
        }
    }

    public static class Config {
        public static Config fromSettings(Settings settings) {
            return new Config(settings.get(ConfigConstants.SECURITY_MASKED_FIELDS_ALGORITHM_DEFAULT), Salt.from(settings));
        }

        public static final Config DEFAULT = fromSettings(Settings.EMPTY);

        private final String defaultHashAlgorithm;
        private final Salt salt;

        Config(String defaultHashAlgorithm, Salt salt) {
            this.defaultHashAlgorithm = defaultHashAlgorithm;
            this.salt = salt;
        }

        public String getDefaultHashAlgorithm() {
            return defaultHashAlgorithm;
        }

        public Salt getSalt() {
            return salt;
        }
    }

}
