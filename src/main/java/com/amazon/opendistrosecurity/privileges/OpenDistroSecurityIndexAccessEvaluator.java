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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistrosecurity.privileges;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;

import com.amazon.opendistrosecurity.auditlog.AuditLog;
import com.amazon.opendistrosecurity.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistrosecurity.support.ConfigConstants;
import com.amazon.opendistrosecurity.support.WildcardMatcher;

public class OpenDistroSecurityIndexAccessEvaluator {
    
    protected final Logger log = LogManager.getLogger(this.getClass());
    
    private final String opendistrosecurityIndex;
    private final AuditLog auditLog;
    private final String[] sgDeniedActionPatternsAll;
    private final String[] sgDeniedActionPatternsSnapshotRestoreAllowed;

    private final boolean restoreSecurityIndexEnabled;
    
    public OpenDistroSecurityIndexAccessEvaluator(final Settings settings, AuditLog auditLog) {
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTROSECURITY_CONFIG_INDEX_NAME, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        this.auditLog = auditLog;
        
        final List<String> securityIndexdeniedActionPatternsListAll = new ArrayList<String>();
        securityIndexdeniedActionPatternsListAll.add("indices:data/write*");
        securityIndexdeniedActionPatternsListAll.add("indices:admin/close");
        securityIndexdeniedActionPatternsListAll.add("indices:admin/delete");
        securityIndexdeniedActionPatternsListAll.add("cluster:admin/snapshot/restore");

        sgDeniedActionPatternsAll = securityIndexdeniedActionPatternsListAll.toArray(new String[0]);

        final List<String> securityIndexdeniedActionPatternsListSnapshotRestoreAllowed = new ArrayList<String>();
        securityIndexdeniedActionPatternsListAll.add("indices:data/write*");
        securityIndexdeniedActionPatternsListAll.add("indices:admin/delete");
              
        sgDeniedActionPatternsSnapshotRestoreAllowed = securityIndexdeniedActionPatternsListSnapshotRestoreAllowed.toArray(new String[0]);
        
        this.restoreSecurityIndexEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTROSECURITY_UNSUPPORTED_RESTORE_SGINDEX_ENABLED, false);
    }
    
    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final Task task, final String action, final Resolved requestedResolved,
            final PrivilegesEvaluatorResponse presponse)  {
        
        final String[] sgDeniedActionPatterns = this.restoreSecurityIndexEnabled? sgDeniedActionPatternsSnapshotRestoreAllowed : sgDeniedActionPatternsAll;
        
        if (requestedResolved.getAllIndices().contains(opendistrosecurityIndex)
                && WildcardMatcher.matchAny(sgDeniedActionPatterns, action)) {
            auditLog.logSecurityIndexAttempt(request, action, task);
            log.warn(action + " for '{}' index is not allowed for a regular user", opendistrosecurityIndex);
            presponse.allowed = false;
            return presponse.markComplete();
        }

        //TODO: newpeval: check if isAll() is all (contains("_all" or "*"))
        if (requestedResolved.isAll()
                && WildcardMatcher.matchAny(sgDeniedActionPatterns, action)) {
            auditLog.logSecurityIndexAttempt(request, action, task);
            log.warn(action + " for '_all' indices is not allowed for a regular user");
            presponse.allowed = false;
            return presponse.markComplete();
        }

      //TODO: newpeval: check if isAll() is all (contains("_all" or "*"))
        if(requestedResolved.getAllIndices().contains(opendistrosecurityIndex) || requestedResolved.isAll()) {

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
