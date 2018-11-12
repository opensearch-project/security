/*
 * Copyright 2015-2018 floragunn GmbH
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

package com.floragunn.searchguard.privileges;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.resolver.IndexResolverReplacer.Resolved;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;

public class SearchGuardIndexAccessEvaluator {
    
    protected final Logger log = LogManager.getLogger(this.getClass());
    
    private final String searchguardIndex;
    private final AuditLog auditLog;
    private final String[] sgDeniedActionPatternsAll;
    private final String[] sgDeniedActionPatternsSnapshotRestoreAllowed;

    private final boolean restoreSgIndexEnabled;
    
    public SearchGuardIndexAccessEvaluator(final Settings settings, AuditLog auditLog) {
        this.searchguardIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        this.auditLog = auditLog;
        
        final List<String> sgIndexdeniedActionPatternsListAll = new ArrayList<String>();
        sgIndexdeniedActionPatternsListAll.add("indices:data/write*");
        sgIndexdeniedActionPatternsListAll.add("indices:admin/close");
        sgIndexdeniedActionPatternsListAll.add("indices:admin/delete");
        sgIndexdeniedActionPatternsListAll.add("cluster:admin/snapshot/restore");

        sgDeniedActionPatternsAll = sgIndexdeniedActionPatternsListAll.toArray(new String[0]);

        final List<String> sgIndexdeniedActionPatternsListSnapshotRestoreAllowed = new ArrayList<String>();
        sgIndexdeniedActionPatternsListAll.add("indices:data/write*");
        sgIndexdeniedActionPatternsListAll.add("indices:admin/delete");
              
        sgDeniedActionPatternsSnapshotRestoreAllowed = sgIndexdeniedActionPatternsListSnapshotRestoreAllowed.toArray(new String[0]);
        
        this.restoreSgIndexEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_UNSUPPORTED_RESTORE_SGINDEX_ENABLED, false);
    }
    
    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final Task task, final String action, final Resolved requestedResolved,
            final PrivilegesEvaluatorResponse presponse)  {
        
        final String[] sgDeniedActionPatterns = this.restoreSgIndexEnabled? sgDeniedActionPatternsSnapshotRestoreAllowed : sgDeniedActionPatternsAll;
        
        if (requestedResolved.getAllIndices().contains(searchguardIndex)
                && WildcardMatcher.matchAny(sgDeniedActionPatterns, action)) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " for '{}' index is not allowed for a regular user", searchguardIndex);
            presponse.allowed = false;
            return presponse.markComplete();
        }

        //TODO: newpeval: check if isAll() is all (contains("_all" or "*"))
        if (requestedResolved.isAll()
                && WildcardMatcher.matchAny(sgDeniedActionPatterns, action)) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " for '_all' indices is not allowed for a regular user");
            presponse.allowed = false;
            return presponse.markComplete();
        }

      //TODO: newpeval: check if isAll() is all (contains("_all" or "*"))
        if(requestedResolved.getAllIndices().contains(searchguardIndex) || requestedResolved.isAll()) {

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
