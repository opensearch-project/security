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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.security.support.WildcardMatcher;

/**
 * Aggregates index patterns defined in roles and segments them into patterns using template expressions ("index_${user.name}"),
 * patterns using date math and plain patterns. This segmentation is needed because only plain patterns can be used
 * to pre-compute privilege maps. The other types of patterns need to be evaluated "live" during the actual request.
 */
public class IndexPattern {
    private static final Logger log = LogManager.getLogger(IndexPattern.class);

    /**
     * An IndexPattern which does not match any index.
     */
    public static final IndexPattern EMPTY = new IndexPattern(
        ImmutableList.of(),
        WildcardMatcher.NONE,
        WildcardMatcher.NONE,
        ImmutableSet.of(),
        ImmutableSet.of(),
        ImmutableList.of(),
        ImmutableList.of()
    );

    /**
     * The original strings used to compile this index pattern.
     */
    private final ImmutableList<String> source;

    /**
     * Plain index patterns without any dynamic expressions like user attributes.
     * This can be not null. If this instance cannot match any static pattern, this will be WildcardMatcher.NONE.
     */
    private final WildcardMatcher staticPattern;

    /**
     * Plain index patterns without any dynamic expressions like user attributes and date math AND which are NOT
     * staticConstantValuePatterns and NOT staticPrefixPatterns.
     * This can be not null. If this instance cannot match any static pattern, this will be WildcardMatcher.NONE.
     */
    private final WildcardMatcher staticPatternWithoutConstantAndPrefixPatterns;

    /**
     * Plain index patterns without any dynamic expressions like user attributes which are static constant values (like "index-2023-01-01").
     */
    private final ImmutableSet<String> staticExactValues;

    /**
     * Plain index patterns without any dynamic expressions like user attributes which are static prefix patterns (like "index-*").
     * The strings in this set are the prefix patterns without the trailing wildcard (like "index-").
     */
    private final ImmutableSet<String> staticPrefixPatterns;

    /**
     * Index patterns which contain user attributes (like ${user.name})
     */
    private final ImmutableList<String> patternTemplates;

    /**
     * Index patterns which contain date math (like <index_{now}>)
     */
    private final ImmutableList<String> dateMathExpressions;
    private final int hashCode;

    private IndexPattern(
        ImmutableList<String> source,
        WildcardMatcher staticPattern,
        WildcardMatcher staticPatternWithoutConstantAndPrefixPattern,
        ImmutableSet<String> staticExactValues,
        ImmutableSet<String> staticPrefixPatterns,
        ImmutableList<String> patternTemplates,
        ImmutableList<String> dateMathExpressions
    ) {
        this.source = source;
        this.staticPattern = staticPattern;
        this.patternTemplates = patternTemplates;
        this.dateMathExpressions = dateMathExpressions;
        this.staticExactValues = staticExactValues;
        this.staticPatternWithoutConstantAndPrefixPatterns = staticPatternWithoutConstantAndPrefixPattern;
        this.staticPrefixPatterns = staticPrefixPatterns;
        this.hashCode = staticPattern.hashCode() + patternTemplates.hashCode() + dateMathExpressions.hashCode();
    }

    public ImmutableList<String> source() {
        return source;
    }

    public boolean isMatchAll() {
        return staticPattern == WildcardMatcher.ANY;
    }

    public boolean matches(String index, PrivilegesEvaluationContext context, Map<String, IndexAbstraction> indexMetadata)
        throws PrivilegesEvaluationException {
        if (staticPattern != WildcardMatcher.NONE && staticPattern.test(index)) {
            return true;
        }

        if (!patternTemplates.isEmpty()) {
            for (String patternTemplate : this.patternTemplates) {
                try {
                    WildcardMatcher matcher = context.getRenderedMatcher(patternTemplate);

                    if (matcher.test(index)) {
                        return true;
                    }
                } catch (ExpressionEvaluationException e) {
                    throw new PrivilegesEvaluationException("Error while evaluating dynamic index pattern: " + patternTemplate, e);
                }
            }
        }

        if (!dateMathExpressions.isEmpty()) {
            IndexNameExpressionResolver indexNameExpressionResolver = context.getIndexNameExpressionResolver();

            // Note: The use of date math expressions in privileges is a bit odd, as it only provides a very limited
            // solution for the potential user case. A different approach might be nice.

            for (String dateMathExpression : this.dateMathExpressions) {
                try {
                    String resolvedExpression = indexNameExpressionResolver.resolveDateMathExpression(dateMathExpression);

                    WildcardMatcher matcher = WildcardMatcher.from(resolvedExpression);

                    if (matcher.test(index)) {
                        return true;
                    }
                } catch (Exception e) {
                    throw new PrivilegesEvaluationException("Error while evaluating date math expression: " + dateMathExpression, e);
                }
            }
        }

        IndexAbstraction indexAbstraction = indexMetadata.get(index);

        if (indexAbstraction instanceof IndexAbstraction.Index) {
            // Check for the privilege for aliases or data streams containing this index

            if (indexAbstraction.getParentDataStream() != null) {
                if (matches(indexAbstraction.getParentDataStream().getName(), context, indexMetadata)) {
                    return true;
                }
            }

            // Retrieve aliases: The use of getWriteIndex() is a bit messy, but it is the only way to access
            // alias metadata from here.
            for (String alias : indexAbstraction.getWriteIndex().getAliases().keySet()) {
                if (matches(alias, context, indexMetadata)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns the indices matching the non-dynamic patterns in this object.
     */
    public Collection<IndexAbstraction> matchingNonDynamic(SortedMap<String, IndexAbstraction> indices)
        throws PrivilegesEvaluationException {
        if (this.staticPatternWithoutConstantAndPrefixPatterns == WildcardMatcher.ANY) {
            return indices.values();
        }

        List<IndexAbstraction> result = new ArrayList<>();

        if (!this.staticExactValues.isEmpty()) {
            for (String staticExactValue : this.staticExactValues) {
                IndexAbstraction indexAbstraction = indices.get(staticExactValue);
                if (indexAbstraction != null) {
                    result.add(indexAbstraction);
                }
            }
        }

        if (!this.staticPrefixPatterns.isEmpty()) {
            for (String staticPrefixPattern : this.staticPrefixPatterns) {
                String toKey = staticPrefixPattern + Character.MAX_VALUE;
                result.addAll(indices.subMap(staticPrefixPattern, toKey).values());
            }
        }

        if (this.staticPatternWithoutConstantAndPrefixPatterns != WildcardMatcher.NONE) {
            for (Map.Entry<String, IndexAbstraction> entry : indices.entrySet()) {
                if (staticPatternWithoutConstantAndPrefixPatterns.test(entry.getKey())) {
                    result.add(entry.getValue());
                }
            }
        }

        return result;
    }

    @Override
    public String toString() {
        if (patternTemplates.size() == 0 && dateMathExpressions.size() == 0) {
            return staticPattern.toString();
        } else {
            StringBuilder result = new StringBuilder();

            if (staticPattern != WildcardMatcher.NONE) {
                result.append(staticPattern);
            }

            if (patternTemplates.size() != 0) {
                if (result.length() != 0) {
                    result.append(" ");
                }

                result.append(String.join(",", patternTemplates));
            }

            if (dateMathExpressions.size() != 0) {
                if (result.length() != 0) {
                    result.append(" ");
                }

                result.append(String.join(",", dateMathExpressions));
            }

            return result.toString();
        }
    }

    public WildcardMatcher getStaticPattern() {
        return staticPattern;
    }

    /**
     * Returns true if this object contains patterns which can be matched against indices upfront.
     */
    public boolean hasStaticPattern() {
        return staticPattern != WildcardMatcher.NONE;
    }

    /**
     * Returns true if this object contains patterns which must be matched against indices again for each request,
     * as they depend on user attributes or on the current time.
     */
    public boolean hasDynamicPattern() {
        return !patternTemplates.isEmpty() || !dateMathExpressions.isEmpty();
    }

    /**
     * Returns a sub-set of this object, which includes only the patterns which must be matched against indices again for each request,
     * as they depend on user attributes or on the current time.
     */
    public IndexPattern dynamicOnly() {
        if (patternTemplates.isEmpty() && dateMathExpressions.isEmpty()) {
            return EMPTY;
        } else {
            return new IndexPattern(
                this.source,
                WildcardMatcher.NONE,
                WildcardMatcher.NONE,
                ImmutableSet.of(),
                ImmutableSet.of(),
                this.patternTemplates,
                this.dateMathExpressions
            );
        }
    }

    /**
     * Returns true if this object cannot match against any index name.
     */
    public boolean isEmpty() {
        return !hasStaticPattern() && !hasDynamicPattern();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IndexPattern that)) return false;
        return Objects.equals(staticPattern, that.staticPattern)
            && Objects.equals(patternTemplates, that.patternTemplates)
            && Objects.equals(dateMathExpressions, that.dateMathExpressions);
    }

    @Override
    public int hashCode() {
        return hashCode;
    }

    public static class Builder {
        private List<String> source = new ArrayList<>();
        private List<WildcardMatcher> nonDynamicPatterns = new ArrayList<>();
        private List<String> patternTemplates = new ArrayList<>();
        private List<String> dateMathExpressions = new ArrayList<>();
        private List<String> nonDynamicExactPatterns = new ArrayList<>();
        private List<String> nonDynamicPrefixPatterns = new ArrayList<>();
        private List<String> nonDynamicPatternsWithoutExactAndPrefixPatterns = new ArrayList<>();

        public void add(List<String> source) {
            this.source.addAll(source);
            for (int i = 0; i < source.size(); i++) {
                try {
                    String indexPattern = source.get(i);

                    if (indexPattern.startsWith("<") && indexPattern.endsWith(">")) {
                        this.dateMathExpressions.add(indexPattern);
                    } else if (!UserAttributes.needsAttributeSubstitution(indexPattern)) {
                        this.nonDynamicPatterns.add(WildcardMatcher.from(indexPattern));

                        if (WildcardMatcher.isExactPattern(indexPattern)) {
                            this.nonDynamicExactPatterns.add(indexPattern);
                        } else if (WildcardMatcher.isPrefixPattern(indexPattern)) {
                            this.nonDynamicPrefixPatterns.add(indexPattern.substring(0, indexPattern.length() - 1));
                        } else {
                            this.nonDynamicPatternsWithoutExactAndPrefixPatterns.add(indexPattern);
                        }
                    } else {
                        this.patternTemplates.add(indexPattern);
                    }
                } catch (Exception e) {
                    // This usually happens when the index pattern defines an unparseable regular expression
                    log.error("Error while creating index pattern for {}", source, e);
                }
            }
        }

        public IndexPattern build() {
            return new IndexPattern(
                ImmutableList.copyOf(source),
                nonDynamicPatterns.size() != 0 ? WildcardMatcher.from(nonDynamicPatterns) : WildcardMatcher.NONE,
                nonDynamicPatternsWithoutExactAndPrefixPatterns.size() != 0
                    ? WildcardMatcher.from(nonDynamicPatternsWithoutExactAndPrefixPatterns)
                    : WildcardMatcher.NONE,
                ImmutableSet.copyOf(nonDynamicExactPatterns),
                ImmutableSet.copyOf(nonDynamicPrefixPatterns),
                ImmutableList.copyOf(patternTemplates),
                ImmutableList.copyOf(dateMathExpressions)
            );
        }
    }

    public static IndexPattern from(List<String> source) {
        Builder builder = new Builder();
        builder.add(source);
        return builder.build();
    }

    public static IndexPattern from(String... source) {
        return from(Arrays.asList(source));
    }
}
