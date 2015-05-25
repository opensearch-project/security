/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.filter.level;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.lucene.index.Term;
import org.apache.lucene.queries.TermFilter;
import org.apache.lucene.search.FieldValueFilter;
import org.apache.lucene.search.Filter;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.collect.ImmutableMap;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.lucene.search.AndFilter;
import org.elasticsearch.common.lucene.search.NotFilter;
import org.elasticsearch.common.lucene.search.OrFilter;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.query.ParsedFilter;
import org.elasticsearch.search.fetch.partial.PartialFieldsContext;
import org.elasticsearch.search.fetch.partial.PartialFieldsContext.PartialField;
import org.elasticsearch.search.fetch.source.FetchSourceContext;
import org.elasticsearch.search.internal.SearchContext;
import org.elasticsearch.search.internal.ShardSearchRequest;
import org.elasticsearch.search.internal.ShardSearchTransportRequest;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.audit.AuditListener;
import com.floragunn.searchguard.authentication.LdapUser;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.service.SearchGuardService;
import com.floragunn.searchguard.tokeneval.TokenEvaluator.Evaluator;
import com.floragunn.searchguard.tokeneval.TokenEvaluator.FilterAction;
import com.floragunn.searchguard.util.SecurityUtil;

public class ConfigurableSearchContextCallback implements SearchContextCallback {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final AuditListener auditListener;

    public ConfigurableSearchContextCallback(final Settings settings, final AuditListener auditListener) {

        if (auditListener == null) {
            throw new IllegalArgumentException("auditListener must not be null");
        }
        this.auditListener = auditListener;

    }

    private static <T> T getFromContextOrHeader(final String key, final TransportRequest request, final T defaultValue) {

        if (request.hasInContext(key)) {
            return request.getFromContext(key);
        }

        if (request.hasHeader(key)) {
            return (T) SecurityUtil.decryptAnDeserializeObject((String) request.getHeader(key), SearchGuardService.getSecretKey());
        }

        return defaultValue;
    }

    @Override
    public void onCreateContext(final SearchContext context, final ShardSearchRequest ssRequest) {
        try {
            onCreateContext0(context, ssRequest);
        } catch (final Exception e) {
            log.error("Error onCreateContext() {} ", e, e.toString());
            throw new RuntimeException(e);
        }
    }

    private void onCreateContext0(final SearchContext context, final ShardSearchRequest ssRequest) {

        if (ssRequest instanceof ShardSearchTransportRequest) {
            final ShardSearchTransportRequest request = (ShardSearchTransportRequest) ssRequest;

            final List<String> filter = getFromContextOrHeader("searchguard_filter", request, Collections.EMPTY_LIST);

            if (filter.size() == 0) {
                log.trace("No filters, skip");
                return;
            }

            final Evaluator evaluator = getFromContextOrHeader("searchguard_ac_evaluator", request, (Evaluator) null);
            final User user = getFromContextOrHeader("searchguard_authenticated_user", request, null);

            if (request.remoteAddress() == null && user == null) {
                log.trace("Return on INTERNODE request");
                return;
            }

            if (evaluator.getBypassAll() && user != null) {
                log.trace("Return on WILDCARD for " + user);
                return;
            }

            //log.trace("user {}", user);

            final Object authHeader = getFromContextOrHeader("searchguard_authenticated_transport_request", request, null);

            if (user == null) {

                if (authHeader == null || !(authHeader instanceof String)) {
                    log.error("not authenticated");
                    throw new ElasticsearchException("not authenticated");
                }

                final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, SearchGuardService.getSecretKey());

                if (decrypted == null || !(decrypted instanceof String) || !decrypted.equals("authorized")) {
                    log.error("bad authenticated");
                    throw new ElasticsearchException("bad authentication");
                }

            }

            //here we know that we either have a non null user or an internally authenticated internode request

            //log.debug("filterNames {}", filterNames);
            //log.debug("filterTypes {}", filterTypes);

            log.trace("filter for {}", filter);

            for (int i = 0; i < filter.size(); i++) {
                final String[] f = filter.get(i).split(":");
                final String ft = f[0];
                final String fn = f[1];

                if (!ft.contains("dlsfilter") && !ft.contains("flsfilter")) {
                    log.trace("    {} skipped here", ft);
                    continue;
                }

                log.trace("Apply {}/{} for {}", ft, fn, request.getClass());

                final FilterAction faction = evaluator.evaluateFilter(ft, fn);

                if (faction == FilterAction.BYPASS) {
                    log.debug("will bypass");
                    continue;
                }

                log.trace("Modifiy search context for node {} and index {} requested from {} and {}/{}", context.shardTarget().nodeId(),
                        Arrays.toString(request.indices()), request.remoteAddress(), ft, fn);

                if ("dlsfilter".equals(ft)) {
                    final List<String> list = getFromContextOrHeader("searchguard." + ft + "." + fn + ".filters", request,
                            Collections.EMPTY_LIST);

                    //log.trace("filterStrings {}", list);

                    final ParsedFilter origfilter = context.parsedPostFilter();
                    final List<Filter> fliste = new ArrayList<Filter>();

                    if (list.isEmpty()) {
                        continue;
                    }

                    final String tfilterType = list.get(0);

                    log.trace("DLS: {} {}", tfilterType, list);

                    switch (tfilterType) {

                        case "term": {

                            final boolean negate = Boolean.parseBoolean(list.get(3));

                            if (negate) {
                                fliste.add(new NotFilter(new TermFilter(new Term(list.get(1), list.get(2)))));
                            } else {
                                fliste.add(new TermFilter(new Term(list.get(1), list.get(2))));
                            }

                        }
                            ;
                            break;
                        case "user_name": {

                            if (user == null) {
                                throw new ElasticsearchException("user is null");
                            }

                            final String field = list.get(1);
                            final boolean negate = Boolean.parseBoolean(list.get(2));
                            final String username = user.getName();

                            if (negate) {
                                fliste.add(new NotFilter(new TermFilter(new Term(field, username))));
                            } else {
                                fliste.add(new TermFilter(new Term(field, username)));
                            }

                        }
                            ;
                            break;
                        case "user_roles": {

                            if (user == null) {
                                throw new ElasticsearchException("user is null");
                            }

                            final String field = list.get(1);
                            final boolean negate = Boolean.parseBoolean(list.get(2));

                            final List<Filter> inner = new ArrayList<Filter>();
                            for (final Iterator iterator = user.getRoles().iterator(); iterator.hasNext();) {
                                final String role = (String) iterator.next();

                                if (negate) {
                                    inner.add(new NotFilter(new TermFilter(new Term(field, role))));
                                } else {
                                    inner.add(new TermFilter(new Term(field, role)));
                                }

                            }
                            if (negate) {
                                fliste.add(new AndFilter(inner));
                            } else {
                                fliste.add(new OrFilter(inner));
                            }

                        }
                            ;
                            break;
                        case "ldap_user_attribute": {

                            if (user == null) {
                                throw new ElasticsearchException("user is null");
                            }

                            if (!(user instanceof LdapUser)) {
                                throw new ElasticsearchException("user is not an ldapuser");
                            }

                            final LdapUser ldapUser = (LdapUser) user;

                            final String field = list.get(1);
                            final String attribute = list.get(2);
                            final boolean negate = Boolean.parseBoolean(list.get(3));
                            final Attribute attr = ldapUser.getUserEntry().get(attribute);

                            if (attribute == null) {
                                break;
                            }

                            try {
                                if (negate) {
                                    fliste.add(new NotFilter(new TermFilter(new Term(field, attr.getString()))));
                                } else {
                                    fliste.add(new TermFilter(new Term(field, attr.getString())));
                                }
                            } catch (final LdapInvalidAttributeValueException e) {
                                //no-op
                            }

                        }
                            ;
                            break;
                        case "ldap_user_roles": {

                            if (user == null) {
                                throw new ElasticsearchException("user is null");
                            }

                            if (!(user instanceof LdapUser)) {
                                throw new ElasticsearchException("user is not an ldapuser");
                            }

                            final LdapUser ldapUser = (LdapUser) user;

                            final String field = list.get(1);
                            final String attribute = list.get(2);
                            final boolean negate = Boolean.parseBoolean(list.get(3));

                            final List<Filter> inner = new ArrayList<Filter>();
                            for (final Iterator<Entry> iterator = ldapUser.getRoleEntries().iterator(); iterator.hasNext();) {
                                final Entry roleEntry = iterator.next();

                                try {
                                    if (negate) {
                                        inner.add(new NotFilter(new TermFilter(new Term(field, roleEntry.get(attribute).getString()))));
                                    } else {
                                        inner.add(new TermFilter(new Term(field, roleEntry.get(attribute).getString())));
                                    }
                                } catch (final LdapInvalidAttributeValueException e) {
                                    //no-op
                                }

                            }
                            if (negate) {
                                fliste.add(new AndFilter(inner));
                            } else {
                                fliste.add(new OrFilter(inner));
                            }

                        }
                            ;
                            break;
                        case "exists": {
                            fliste.add(new FieldValueFilter(list.get(1), Boolean.parseBoolean(list.get(2))));
                        }
                            ;
                            break;
                    }

                    //log.trace("dls extra filters {}", fliste);

                    if (origfilter == null) {
                        context.parsedPostFilter(new ParsedFilter(new AndFilter(fliste), ImmutableMap.<String, Filter> builder().build()));
                    } else {
                        fliste.add(origfilter.filter());
                        context.parsedPostFilter(new ParsedFilter(new AndFilter(fliste), origfilter.namedFilters()));
                    }

                }

                if ("flsfilter".equals(ft)) {

                    final List<String> sourceIncludes = getFromContextOrHeader("searchguard." + ft + "." + fn + ".source_includes",
                            request, Collections.EMPTY_LIST);
                    final List<String> sourceExcludes = getFromContextOrHeader("searchguard." + ft + "." + fn + ".source_excludes",
                            request, Collections.EMPTY_LIST);

                    log.trace("fls sourceIncludes {}", sourceIncludes);
                    log.trace("fls sourceExcludes {}", sourceExcludes);
                    boolean fieldsDone = false;

                    if (context.hasFieldNames()) {
                        fieldsDone = true;
                        final List<String> fields = context.fieldNames();
                        final List<String> survivingFields = new ArrayList<String>(fields);
                        for (final Iterator<String> iterator = fields.iterator(); iterator.hasNext();) {
                            final String field = iterator.next();

                            for (final Iterator<String> iteratorExcludes = sourceExcludes.iterator(); iteratorExcludes.hasNext();) {
                                final String exclude = iteratorExcludes.next();
                                if (SecurityUtil.isWildcardMatch(field, exclude, false)) {
                                    survivingFields.remove(field);
                                }

                            }

                            /*for (Iterator<String> iteratorIncludes = sourceIncludes.iterator(); iteratorIncludes.hasNext();) {
                                String include = iteratorIncludes.next();
                                if(SecurityUtil.isWildcardMatch(field, include, false)) {
                                    if(!survivingFields.contains(field)) {
                                        survivingFields.add(field);
                                    }
                                }

                            }*/

                        }

                        log.trace("survivingFields {}", survivingFields.equals(fields) ? "-all-" : survivingFields.toString());
                        fields.retainAll(survivingFields);
                    }

                    if (context.hasPartialFields()) {
                        fieldsDone = true;
                        final PartialFieldsContext partialFieldsContext = context.partialFields();
                        final List<PartialField> partialFields = partialFieldsContext.fields();
                        final List<PartialField> survivingFields = new ArrayList<PartialField>(partialFields);
                        for (final Iterator<PartialField> iterator = partialFields.iterator(); iterator.hasNext();) {
                            final PartialField field = iterator.next();

                            for (final Iterator<String> iteratorExcludes = sourceExcludes.iterator(); iteratorExcludes.hasNext();) {
                                final String exclude = iteratorExcludes.next();
                                final String[] fieldExcludes = field.includes();

                                for (int j = 0; j < fieldExcludes.length; j++) {
                                    if (SecurityUtil.isWildcardMatch(fieldExcludes[j], exclude, false)) {
                                        survivingFields.remove(field);
                                    }
                                }
                            }

                            /*for (Iterator<String> iteratorIncludes = sourceIncludes.iterator(); iteratorIncludes.hasNext();) {
                                String include = iteratorIncludes.next();
                                if(SecurityUtil.isWildcardMatch(field, include, false)) {
                                    if(!survivingFields.contains(field)) {
                                        survivingFields.add(field);
                                    }
                                }

                            }*/

                        }

                        log.trace("survivingPartialFields {}", survivingFields.equals(partialFields) ? "-all-" : survivingFields.toString());
                        partialFields.retainAll(survivingFields);
                    }

                    //TODO FUTURE include exclude precedence, what if null or empty?

                    if (!fieldsDone) {

                        context.fetchSourceContext(new FetchSourceContext(sourceIncludes.size() == 0 ? null : sourceIncludes
                                .toArray(new String[0]), sourceExcludes.size() == 0 ? null : sourceExcludes.toArray(new String[0])));
                    }

                }
            }

        } else {
            log.error("Cannot add DLS/FLS to a local ShardSearchRequest, {} not supported", ssRequest.getClass());
            throw new ElasticsearchException("Cannot add DLS/FLS to a local ShardSearchRequest, " + ssRequest.getClass() + " not supported");
        }
    }
}
