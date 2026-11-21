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
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import org.apache.commons.lang3.StringUtils;
import org.apache.lucene.util.BytesRef;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.Salt;
import org.opensearch.security.privileges.CompiledRoles;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
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
        CompiledRoles compiledRoles,
        SortedMap<String, IndexAbstraction> indexMetadata,
        FieldMasking.Config fieldMaskingConfig,
        Settings settings
    ) {
        super(compiledRoles, indexMetadata, (indexPermissions) -> indexPermissions.maskedFields, settings);
        this.fieldMaskingConfig = fieldMaskingConfig;
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

            public SimpleRule(RoleV7.Index sourceIndex, FieldMasking.Config fieldMaskingConfig)
                throws PrivilegesConfigurationValidationException {
                this.sourceIndex = sourceIndex;
                this.expressions = parseExpressions(sourceIndex, fieldMaskingConfig);
            }

            SimpleRule(ImmutableList<Field> expressions) {
                this.sourceIndex = null;
                this.expressions = expressions;
            }

            public Field get(String field) {
                return internalGet(FieldPrivileges.normalizeFieldName(field));
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
                field = FieldPrivileges.normalizeFieldName(field);

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
            private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

            /**
             * Size of the thread-local scratch buffer used to hold raw hash results before hex encoding.
             * 64 bytes covers all standard MessageDigest algorithms (e.g. SHA-512) and the 32 byte Blake2b
             * digest used for field masking.
             */
            private static final int DIGEST_SCRATCH_SIZE = 64;

            private final FieldMaskingExpression expression;

            private final String hashAlgorithm;
            private final Salt salt;
            private final byte[] saltBytes;
            private final boolean useLegacyDefaultAlgorithm;

            /**
             * Per-thread cache of {@link MessageDigest} instances keyed by algorithm name.
             * {@link MessageDigest} is not thread-safe, so each thread gets its own instance; the map is
             * bounded by the number of distinct configured hash algorithms (usually a single one), so it
             * cannot grow without bound. The cache is scoped to this {@code Field} instance (not static)
             * so that no state is retained on long-lived threads beyond the lifetime of this instance and
             * the classloader that loaded it. Instances are reset after every digest() call.
             */
            private final ThreadLocal<Map<String, MessageDigest>> messageDigests = ThreadLocal.withInitial(HashMap::new);

            /**
             * Per-thread scratch buffer for raw (non hex-encoded) hash results, reused across invocations
             * to avoid one allocation per masked value. Scoped to this {@code Field} instance for the same
             * reason as {@link #messageDigests}.
             */
            private final ThreadLocal<byte[]> digestScratch = ThreadLocal.withInitial(() -> new byte[DIGEST_SCRATCH_SIZE]);

            /**
             * Reusable per-thread Blake2b instances (normal and legacy parameterization). Blake2b is not
             * thread-safe; {@code digest()} leaves the instance in a reset state with the salt retained,
             * so the instance can safely be reused instead of allocating a new one per masked value.
             * <p>
             * The ThreadLocals are deliberately created WITHOUT a supplier: spinning up a lambda whose
             * return type is {@code Blake2b} would resolve the {@code Blake2b} class already in the
             * constructor of {@code Field}. {@code Field} instances are constructed for every index
             * (e.g. via {@link FieldMasking#fullyRestricted()}), including in classpath-plugin deployments
             * (e.g. the sample-resource-plugin integration tests) where the security plugin classes are
             * visible but the bundled blake2b jar is not, which would fail with
             * {@code NoClassDefFoundError}. The {@code Blake2b} instance is therefore created lazily in
             * {@link #blake2bHash}, i.e. only when a value is actually hashed.
             */
            private final ThreadLocal<Blake2b> blake2b = new ThreadLocal<>();
            private final ThreadLocal<Blake2b> blake2bLegacy = new ThreadLocal<>();

            Field(FieldMaskingExpression expression, FieldMasking.Config fieldMaskingConfig) {
                this.expression = expression;
                this.hashAlgorithm = expression.getAlgoName() != null ? expression.getAlgoName()
                    : StringUtils.isNotEmpty(fieldMaskingConfig.getDefaultHashAlgorithm()) ? fieldMaskingConfig.getDefaultHashAlgorithm()
                    : null;
                this.useLegacyDefaultAlgorithm = fieldMaskingConfig.useLegacyDefaultAlgorithm();
                this.salt = fieldMaskingConfig.getSalt();
                this.saltBytes = this.salt.getSalt16();
                // Note: no Blake2b reference here on purpose, see the javadoc of blake2b/blake2bLegacy.
            }

            /**
             * Returns a thread-local {@link MessageDigest} for the given algorithm, creating and caching it
             * on first use. This avoids the cost of a provider lookup (and the allocation) of
             * {@code MessageDigest.getInstance()} for every masked field value.
             */
            private MessageDigest messageDigest(String algorithm) {
                final Map<String, MessageDigest> digests = messageDigests.get();
                MessageDigest digest = digests.get(algorithm);
                if (digest == null) {
                    try {
                        digest = MessageDigest.getInstance(algorithm);
                    } catch (NoSuchAlgorithmException e) {
                        throw new IllegalArgumentException(e);
                    }
                    digests.put(algorithm, digest);
                }
                return digest;
            }

            /**
             * Hex-encodes the first {@code length} bytes of {@code in} into a freshly allocated array
             * (lowercase, same output as {@code org.bouncycastle.util.encoders.Hex.encode}).
             */
            private static byte[] hexEncode(byte[] in, int length) {
                final byte[] out = new byte[length * 2];
                for (int i = 0, j = 0; i < length; i++) {
                    final int v = in[i] & 0xFF;
                    out[j++] = (byte) HEX_DIGITS[v >>> 4];
                    out[j++] = (byte) HEX_DIGITS[v & 0x0F];
                }
                return out;
            }

            public WildcardMatcher getPattern() {
                return expression.getPattern();
            }

            public byte[] apply(byte[] value) {
                return apply(value, 0, value.length);
            }

            public String apply(String value) {
                final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                return new String(apply(bytes, 0, bytes.length), StandardCharsets.UTF_8);
            }

            public BytesRef apply(BytesRef value) {
                if (value == null) {
                    return null;
                }

                // Hash the value in place instead of creating a defensive copy of the (potentially large)
                // field value for every masked document. This is called once per masked field value per
                // document, so avoiding the copy significantly reduces allocation pressure and heap
                // usage during searches with field masking enabled.
                // NOTE: apply(byte[], int, int) MUST treat the input array as read-only, since
                // value.bytes may be a shared Lucene-owned buffer. Do not introduce any in-place
                // mutation of the input slice in the hashing or regex paths.
                return new BytesRef(apply(value.bytes, value.offset, value.length));
            }

            private byte[] apply(byte[] value, int offset, int length) {
                if (expression.getRegexReplacements() != null) {
                    return applyRegexReplacements(value, offset, length, expression.getRegexReplacements());
                } else if (this.useLegacyDefaultAlgorithm) {
                    return blake2bHash(value, offset, length, true);
                } else if (this.hashAlgorithm != null) {
                    return customHash(value, offset, length, this.hashAlgorithm);
                } else {
                    return blake2bHash(value, offset, length, false);
                }
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

            private byte[] customHash(byte[] in, int offset, int length, String algorithm) {
                final MessageDigest digest = messageDigest(algorithm);
                final byte[] scratch = digestScratch.get();
                // Reset defensively so a previous use that aborted mid-operation (e.g. a DigestException)
                // cannot leak partial state into this invocation.
                digest.reset();
                if (digest.getDigestLength() > 0 && digest.getDigestLength() <= scratch.length) {
                    // Hash the input slice in place (no copy of the field value) and digest directly
                    // into the reusable thread-local scratch buffer. The digest is reset automatically
                    // after digest() completes, so the thread-local instance can safely be reused.
                    try {
                        digest.update(in, offset, length);
                        final int digestLength = digest.digest(scratch, 0, scratch.length);
                        return hexEncode(scratch, digestLength);
                    } catch (DigestException e) {
                        // Cannot happen: the scratch buffer is pre-checked to be large enough
                        throw new IllegalStateException("Unexpected failure digesting with algorithm " + algorithm, e);
                    }
                }
                // Fallback for exotic algorithms with an unusually large digest size
                digest.update(in, offset, length);
                final byte[] raw = digest.digest();
                return hexEncode(raw, raw.length);
            }

            private byte[] applyRegexReplacements(
                byte[] value,
                int offset,
                int length,
                List<FieldMaskingExpression.RegexReplacement> regexReplacements
            ) {
                String string = new String(value, offset, length, StandardCharsets.UTF_8);
                for (FieldMaskingExpression.RegexReplacement rr : regexReplacements) {
                    string = rr.getRegex().matcher(string).replaceAll(rr.getReplacement());
                }
                return string.getBytes(StandardCharsets.UTF_8);
            }

            private byte[] blake2bHash(byte[] in, int offset, int length, boolean useLegacyDefaultAlgorithm) {
                // Reuse a per-thread Blake2b instance instead of allocating a new one for every masked
                // value. The instance is created lazily here (and NOT in the constructor) so that the
                // Blake2b class is only resolved when a value is actually hashed; Field instances are
                // constructed for every index (e.g. via FieldMasking.fullyRestricted()), including in
                // classpath-plugin deployments where the bundled blake2b jar is not visible.
                final ThreadLocal<Blake2b> cache = useLegacyDefaultAlgorithm ? blake2bLegacy : blake2b;
                Blake2b hash = cache.get();
                if (hash == null) {
                    hash = useLegacyDefaultAlgorithm ? new Blake2b(null, 32, null, saltBytes) : new Blake2b(null, 32, saltBytes, null);
                    cache.set(hash);
                }
                // digest() leaves the instance in a reset state (salt/personalization retained), so it can
                // safely be reused; reset() is called defensively in case a previous use aborted.
                hash.reset();
                hash.update(in, offset, length);
                final byte[] scratch = digestScratch.get();
                // Blake2b is constructed with a fixed 32 byte digest size, which always fits into the
                // 64 byte scratch buffer, so digest(scratch, 0) can never overflow it.
                hash.digest(scratch, 0);
                return hexEncode(scratch, hash.getDigestSize());
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
        public static final String BLAKE2B_LEGACY_DEFAULT = "BLAKE2B_LEGACY_DEFAULT";

        public static Config fromSettings(Settings settings) {
            return new Config(settings.get(ConfigConstants.SECURITY_MASKED_FIELDS_ALGORITHM_DEFAULT), Salt.from(settings));
        }

        public static final Config DEFAULT = fromSettings(Settings.EMPTY);

        private final String defaultHashAlgorithm;
        private final Salt salt;
        private final boolean useLegacyDefaultAlgorithm;

        Config(String defaultHashAlgorithm, Salt salt) {
            this.defaultHashAlgorithm = defaultHashAlgorithm;
            this.salt = salt;
            this.useLegacyDefaultAlgorithm = BLAKE2B_LEGACY_DEFAULT.equalsIgnoreCase(defaultHashAlgorithm);
        }

        public String getDefaultHashAlgorithm() {
            return defaultHashAlgorithm;
        }

        public Salt getSalt() {
            return salt;
        }

        public boolean useLegacyDefaultAlgorithm() {
            return useLegacyDefaultAlgorithm;
        }
    }

}
