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
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.google.common.collect.ImmutableList;
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
    public static final IndexPattern EMPTY = new IndexPattern(WildcardMatcher.NONE, ImmutableList.of(), ImmutableList.of());

    /**
     * Plain index patterns without any dynamic expressions like user attributes and date math.
     * This can be not null. If this instance cannot match any static pattern, this will be WildcardMatcher.NONE.
     */
    private final WildcardMatcher staticPattern;

    /**
     * Index patterns which contain user attributes (like ${user.name})
     */
    private final ImmutableList<String> patternTemplates;

    /**
     * Index patterns which contain date math (like <index_{now}>)
     */
    private final ImmutableList<String> dateMathExpressions;
    private final int hashCode;

    private IndexPattern(WildcardMatcher staticPattern, ImmutableList<String> patternTemplates, ImmutableList<String> dateMathExpressions) {
        this.staticPattern = staticPattern;
        this.patternTemplates = patternTemplates;
        this.dateMathExpressions = dateMathExpressions;
        this.hashCode = staticPattern.hashCode() + patternTemplates.hashCode() + dateMathExpressions.hashCode();
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
            return new IndexPattern(WildcardMatcher.NONE, this.patternTemplates, this.dateMathExpressions);
        }
    }

    /**
     * Returns true if this object cannot match against any index name.
     */
    public boolean isEmpty() {
        return (staticPattern == null || staticPattern == WildcardMatcher.NONE)
            && this.patternTemplates.isEmpty()
            && this.dateMathExpressions.isEmpty();
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

    static class Builder {
        private List<WildcardMatcher> constantPatterns = new ArrayList<>();
        private List<String> patternTemplates = new ArrayList<>();
        private List<String> dateMathExpressions = new ArrayList<>();

        void add(List<String> source) {
            for (int i = 0; i < source.size(); i++) {
                try {
                    String indexPattern = source.get(i);

                    if (indexPattern.startsWith("<") && indexPattern.endsWith(">")) {
                        this.dateMathExpressions.add(indexPattern);
                    } else if (!containsPlaceholder(indexPattern)) {
                        this.constantPatterns.add(WildcardMatcher.from(indexPattern));
                    } else {
                        this.patternTemplates.add(indexPattern);
                    }
                } catch (Exception e) {
                    // This usually happens when the index pattern defines an unparseable regular expression
                    log.error("Error while creating index pattern for {}", source, e);
                }
            }
        }

        IndexPattern build() {
            return new IndexPattern(
                constantPatterns.size() != 0 ? WildcardMatcher.from(constantPatterns) : WildcardMatcher.NONE,
                ImmutableList.copyOf(patternTemplates),
                ImmutableList.copyOf(dateMathExpressions)
            );
        }
    }

    static boolean containsPlaceholder(String indexPattern) {
        return indexPattern.indexOf("${") != -1;
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
