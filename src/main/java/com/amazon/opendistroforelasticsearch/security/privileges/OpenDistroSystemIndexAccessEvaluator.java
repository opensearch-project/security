/*
 * Portions Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;

import java.util.ArrayList;
import java.util.List;

/**
 * Blocks requests for below actions and configured index for all non adminDNs.
 */
public class OpenDistroSystemIndexAccessEvaluator {

    private final Logger log = LogManager.getLogger(this.getClass());

    private final AuditLog auditLog;
    private final WildcardMatcher indexMatcher;
    private final Boolean systemIndexEnabled;
    private final WildcardMatcher deniedActionMatcher;


    public OpenDistroSystemIndexAccessEvaluator(final Settings settings, AuditLog auditLog) {
        this.indexMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_KEY, ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_DEFAULT));
        this.systemIndexEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_ENABLED_KEY, ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_ENABLED_DEFAULT);
        this.auditLog = auditLog;

        final List<String> indexDeniedActionPatterns = new ArrayList<String>();
        indexDeniedActionPatterns.add("indices:data/write*");
        indexDeniedActionPatterns.add("indices:admin/delete*");
        indexDeniedActionPatterns.add("indices:admin/mapping/delete*");
        indexDeniedActionPatterns.add("indices:admin/mapping/put*");
        indexDeniedActionPatterns.add("indices:admin/freeze*");
        indexDeniedActionPatterns.add("indices:admin/settings/update*");
        indexDeniedActionPatterns.add("indices:admin/aliases");
        indexDeniedActionPatterns.add("indices:admin/close*");
        indexDeniedActionPatterns.add("cluster:admin/snapshot/restore*");
        this.deniedActionMatcher = WildcardMatcher.from(indexDeniedActionPatterns);
    }

    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final Task task, final String action,
                                                final IndexResolverReplacer.Resolved requestedResolved, final PrivilegesEvaluatorResponse presponse, final boolean isAdminDn) {

        if (!systemIndexEnabled) {
            return presponse;
        }

        if (indexMatcher.matchAny(requestedResolved.getAllIndices()) && deniedActionMatcher.test(action) && !isAdminDn) {
            auditLog.logMissingPrivileges(action, request, task);
            log.warn(action + " for '{}' index/indices is not allowed for a non adminDN user", indexMatcher);
            presponse.allowed = false;
            return presponse.markComplete();
        }

        if (requestedResolved.isLocalAll() && deniedActionMatcher.test(action) && !isAdminDn) {
            auditLog.logMissingPrivileges(action, request, task);
            log.warn(action + " for '_all' indices is not allowed for a non adminDN user");
            presponse.allowed = false;
            return presponse.markComplete();
        }

        if((indexMatcher.matchAny(requestedResolved.getAllIndices()) || requestedResolved.isLocalAll()) && !isAdminDn) {

            if(request instanceof SearchRequest) {
                ((SearchRequest)request).requestCache(Boolean.FALSE);
                if(log.isDebugEnabled()) {
                    log.debug("Disable search request cache for this request");
                }
            }

            if(request instanceof RealtimeRequest) {
                ((RealtimeRequest) request).realtime(Boolean.FALSE);
                if(log.isDebugEnabled()) {
                    log.debug("Disable realtime for this request");
                }
            }
        }
        return presponse;
    }
}
