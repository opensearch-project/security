/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.RealtimeRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.tasks.Task;

public class SecurityIndexAccessEvaluator {
    
    Logger log = LogManager.getLogger(this.getClass());
    
    private final String securityIndex;
    private final AuditLog auditLog;
    private final WildcardMatcher securityDeniedActionMatcher;
    private final IndexResolverReplacer irr;
    private final boolean filterSecurityIndex;

    // for system-indices configuration
    private final WildcardMatcher systemIndexMatcher;
    private final boolean systemIndexEnabled;

    public SecurityIndexAccessEvaluator(final Settings settings, AuditLog auditLog, IndexResolverReplacer irr) {
        this.securityIndex = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.auditLog = auditLog;
        this.irr = irr;
        this.filterSecurityIndex = settings.getAsBoolean(ConfigConstants.SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS, false);
        this.systemIndexMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, ConfigConstants.SECURITY_SYSTEM_INDICES_DEFAULT));
        this.systemIndexEnabled = settings.getAsBoolean(ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY, ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_DEFAULT);

        final boolean restoreSecurityIndexEnabled = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED, false);

        final List<String> securityIndexDeniedActionPatternsList = new ArrayList<String>();
        securityIndexDeniedActionPatternsList.add("indices:data/write*");
        securityIndexDeniedActionPatternsList.add("indices:admin/delete*");
        securityIndexDeniedActionPatternsList.add("indices:admin/mapping/delete*");
        securityIndexDeniedActionPatternsList.add("indices:admin/mapping/put*");
        securityIndexDeniedActionPatternsList.add("indices:admin/freeze*");
        securityIndexDeniedActionPatternsList.add("indices:admin/settings/update*");
        securityIndexDeniedActionPatternsList.add("indices:admin/aliases");

        final List<String> securityIndexDeniedActionPatternsListNoSnapshot = new ArrayList<String>();
        securityIndexDeniedActionPatternsListNoSnapshot.addAll(securityIndexDeniedActionPatternsList);
        securityIndexDeniedActionPatternsListNoSnapshot.add("indices:admin/close*");
        securityIndexDeniedActionPatternsListNoSnapshot.add("cluster:admin/snapshot/restore*");

        securityDeniedActionMatcher = WildcardMatcher.from(restoreSecurityIndexEnabled ? securityIndexDeniedActionPatternsList : securityIndexDeniedActionPatternsListNoSnapshot);
    }
    
    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final Task task, final String action, final Resolved requestedResolved,
            final PrivilegesEvaluatorResponse presponse)  {
        final boolean isDebugEnabled = log.isDebugEnabled();
        if (securityDeniedActionMatcher.test(action)) {
            if(requestedResolved.isLocalAll()) {
                if(filterSecurityIndex) {
                    irr.replace(request, false, "*","-"+ securityIndex);
                    if (isDebugEnabled) {
                        log.debug("Filtered '{}'from {}, resulting list with *,-{} is {}", securityIndex, requestedResolved, securityIndex, irr.resolveRequest(request));
                    }
                    return presponse;
                } else {
                    auditLog.logSecurityIndexAttempt(request, action, task);
                    log.warn( "{} for '_all' indices is not allowed for a regular user", action);
                    presponse.allowed = false;
                    return presponse.markComplete();
                }
            } else if (matchAnySystemIndices(requestedResolved)) {
                if(filterSecurityIndex) {
                    Set<String> allWithoutSecurity = new HashSet<>(requestedResolved.getAllIndices());
                    allWithoutSecurity.remove(securityIndex);
                    if(allWithoutSecurity.isEmpty()) {
                        if (isDebugEnabled) {
                            log.debug("Filtered '{}' but resulting list is empty", securityIndex);
                        }
                        presponse.allowed = false;
                        return presponse.markComplete();
                    }
                    irr.replace(request, false, allWithoutSecurity.toArray(new String[0]));
                    if (isDebugEnabled) {
                        log.debug("Filtered '{}', resulting list is {}", securityIndex, allWithoutSecurity);
                    }
                    return presponse;
                } else {
                    auditLog.logSecurityIndexAttempt(request, action, task);
                    final String foundSystemIndexes = getProtectedIndexes(requestedResolved).stream().collect(Collectors.joining(", "));
                    log.warn("{} for '{}' index is not allowed for a regular user", action, foundSystemIndexes);
                    presponse.allowed = false;
                    return presponse.markComplete();
                }
            }
        }

        if(requestedResolved.isLocalAll() || requestedResolved.getAllIndices().contains(securityIndex)
                || matchAnySystemIndices(requestedResolved)) {

            if(request instanceof SearchRequest) {
                ((SearchRequest)request).requestCache(Boolean.FALSE);
                if (isDebugEnabled) {
                    log.debug("Disable search request cache for this request");
                }
            }

            if(request instanceof RealtimeRequest) {
                ((RealtimeRequest) request).realtime(Boolean.FALSE);
                if (isDebugEnabled) {
                    log.debug("Disable realtime for this request");
                }
            }
        }
        return presponse;
    }

    private boolean matchAnySystemIndices(final Resolved requestedResolved){
        return !getProtectedIndexes(requestedResolved).isEmpty();
    }

    private List<String> getProtectedIndexes(final Resolved requestedResolved) {
        final List<String> protectedIndexes = requestedResolved.getAllIndices().stream().filter(securityIndex::equals).collect(Collectors.toList());
        if (systemIndexEnabled) {
            protectedIndexes.addAll(systemIndexMatcher.getMatchAny(requestedResolved.getAllIndices(), Collectors.toList()));
        }
        return protectedIndexes;
    }
}
