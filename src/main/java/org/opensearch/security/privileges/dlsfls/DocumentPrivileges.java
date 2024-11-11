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
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.logging.log4j.util.Strings;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.AbstractQueryBuilder;
import org.opensearch.index.query.MatchNoneQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.privileges.UserAttributes;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

/**
 * This class converts role configuration into pre-computed, optimized data structures for checking DLS privileges.
 * <p>
 * With the exception of the statefulRules property, instances of this class are immutable. The life-cycle of an
 * instance of this class corresponds to the life-cycle of the role configuration. If the role configuration is changed,
 * a new instance needs to be built.
 * <p>
 * Instances of this class are managed by DlsFlsProcessedConfig.
 */
public class DocumentPrivileges extends AbstractRuleBasedPrivileges<DocumentPrivileges.DlsQuery, DlsRestriction> {

    private final NamedXContentRegistry xContentRegistry;

    public DocumentPrivileges(
        SecurityDynamicConfiguration<RoleV7> roles,
        Map<String, IndexAbstraction> indexMetadata,
        NamedXContentRegistry xContentRegistry,
        Settings settings
    ) {
        super(roles, indexMetadata, (rolePermissions) -> roleToRule(rolePermissions, xContentRegistry), settings);
        this.xContentRegistry = xContentRegistry;
    }

    static DlsQuery roleToRule(RoleV7.Index rolePermissions, NamedXContentRegistry xContentRegistry)
        throws PrivilegesConfigurationValidationException {
        String dlsQueryTemplate = rolePermissions.getDls();

        if (dlsQueryTemplate != null && !Strings.isBlank(dlsQueryTemplate)) {
            return DlsQuery.create(dlsQueryTemplate, xContentRegistry);
        } else {
            return null;
        }
    }

    @Override
    protected DlsRestriction unrestricted() {
        return DlsRestriction.NONE;
    }

    @Override
    protected DlsRestriction fullyRestricted() {
        return DlsRestriction.FULL;
    }

    @Override
    protected DlsRestriction compile(PrivilegesEvaluationContext context, Collection<DlsQuery> rules) throws PrivilegesEvaluationException {
        List<RenderedDlsQuery> renderedQueries = new ArrayList<>(rules.size());

        for (DlsQuery query : rules) {
            renderedQueries.add(query.evaluate(context));
        }

        return new DlsRestriction(renderedQueries);
    }

    /**
     * The basic rules of DLS are queries. This class encapsulates single queries.
     */
    static abstract class DlsQuery {
        final String queryString;

        DlsQuery(String queryString) {
            this.queryString = queryString;
        }

        abstract RenderedDlsQuery evaluate(PrivilegesEvaluationContext context) throws PrivilegesEvaluationException;

        @Override
        public int hashCode() {
            return queryString.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof DlsQuery)) {
                return false;
            }
            DlsQuery other = (DlsQuery) obj;
            return Objects.equals(this.queryString, other.queryString);
        }

        protected QueryBuilder parseQuery(String queryString, NamedXContentRegistry xContentRegistry)
            throws PrivilegesConfigurationValidationException {
            try {
                XContentParser parser = JsonXContent.jsonXContent.createParser(
                    xContentRegistry,
                    DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                    queryString
                );
                return AbstractQueryBuilder.parseInnerQueryBuilder(parser);
            } catch (Exception e) {
                throw new PrivilegesConfigurationValidationException("Invalid DLS query: " + queryString, e);
            }
        }

        static DlsQuery create(String queryString, NamedXContentRegistry xContentRegistry)
            throws PrivilegesConfigurationValidationException {
            if (queryString.contains("${")) {
                return new DlsQuery.Dynamic(queryString, xContentRegistry);
            } else {
                return new DlsQuery.Constant(queryString, xContentRegistry);
            }
        }

        /**
         * Represents a DLS query WITHOUT user attribute references like "${user.name}". These queries are already
         * pre-parsed and ready for use.
         */
        static class Constant extends DlsQuery {
            private final RenderedDlsQuery renderedDlsQuery;

            Constant(String queryString, NamedXContentRegistry xContentRegistry) throws PrivilegesConfigurationValidationException {
                super(queryString);
                this.renderedDlsQuery = new RenderedDlsQuery(parseQuery(queryString, xContentRegistry), queryString);
            }

            @Override
            RenderedDlsQuery evaluate(PrivilegesEvaluationContext context) {
                return renderedDlsQuery;
            }
        }

        /**
         * Represents a DLS query with user attribute references like "${user.name}". These queries are parsed
         * during privilege evaluation time, after user attribute interpolation has been performed.
         */
        static class Dynamic extends DlsQuery {
            private final NamedXContentRegistry xContentRegistry;

            Dynamic(String queryString, NamedXContentRegistry xContentRegistry) {
                super(queryString);
                this.xContentRegistry = xContentRegistry;
            }

            @Override
            RenderedDlsQuery evaluate(PrivilegesEvaluationContext context) throws PrivilegesEvaluationException {
                String effectiveQueryString = UserAttributes.replaceProperties(this.queryString, context);
                try {
                    return new RenderedDlsQuery(parseQuery(effectiveQueryString, xContentRegistry), effectiveQueryString);
                } catch (Exception e) {
                    throw new PrivilegesEvaluationException("Invalid DLS query: " + effectiveQueryString, e);
                }
            }
        }
    }

    /**
     * This is a DLS query where any templates (like ${user.name}) have been interpolated and which has been
     * succesfully parsed to a QueryBuilder instance.
     */
    public static class RenderedDlsQuery {
        public static RenderedDlsQuery MATCH_NONE = new RenderedDlsQuery(new MatchNoneQueryBuilder(), "{\"match_none:\" {}}");

        private final QueryBuilder queryBuilder;
        private final String renderedSource;

        RenderedDlsQuery(QueryBuilder queryBuilder, String renderedSource) {
            this.queryBuilder = queryBuilder;
            this.renderedSource = renderedSource;
        }

        public QueryBuilder getQueryBuilder() {
            return queryBuilder;
        }

        public String getRenderedSource() {
            return renderedSource;
        }
    }

}
