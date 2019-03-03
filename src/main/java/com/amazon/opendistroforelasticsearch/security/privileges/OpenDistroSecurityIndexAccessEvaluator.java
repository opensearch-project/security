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

package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;

public class OpenDistroSecurityIndexAccessEvaluator {
    
    protected final Logger log = LogManager.getLogger(this.getClass());
    
    private final String opendistrosecurityIndex;
    private final AuditLog auditLog;
    private final String[] securityDeniedActionPatternsAll;
    private final String[] securityDeniedActionPatternsSnapshotRestoreAllowed;

    private final boolean restoreSecurityIndexEnabled;
    
    public OpenDistroSecurityIndexAccessEvaluator(final Settings settings, AuditLog auditLog) {
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.auditLog = auditLog;
        
        final List<String> securityIndexdeniedActionPatternsListAll = new ArrayList<String>();
        securityIndexdeniedActionPatternsListAll.add("indices:data/write*");
        securityIndexdeniedActionPatternsListAll.add("indices:admin/close");
        securityIndexdeniedActionPatternsListAll.add("indices:admin/delete");
        securityIndexdeniedActionPatternsListAll.add("cluster:admin/snapshot/restore");

        securityDeniedActionPatternsAll = securityIndexdeniedActionPatternsListAll.toArray(new String[0]);

        final List<String> securityIndexdeniedActionPatternsListSnapshotRestoreAllowed = new ArrayList<String>();
        securityIndexdeniedActionPatternsListAll.add("indices:data/write*");
        securityIndexdeniedActionPatternsListAll.add("indices:admin/delete");
              
        securityDeniedActionPatternsSnapshotRestoreAllowed = securityIndexdeniedActionPatternsListSnapshotRestoreAllowed.toArray(new String[0]);
        
        this.restoreSecurityIndexEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED, false);
    }
    
    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final Task task, final String action, final Resolved requestedResolved,
            final PrivilegesEvaluatorResponse presponse)  {
        
        final String[] securityDeniedActionPatterns = this.restoreSecurityIndexEnabled? securityDeniedActionPatternsSnapshotRestoreAllowed : securityDeniedActionPatternsAll;
        
        if (requestedResolved.getAllIndices().contains(opendistrosecurityIndex)
                && WildcardMatcher.matchAny(securityDeniedActionPatterns, action)) {
            auditLog.logSecurityIndexAttempt(request, action, task);
            log.warn(action + " for '{}' index is not allowed for a regular user", opendistrosecurityIndex);
            presponse.allowed = false;
            return presponse.markComplete();
        }

        //TODO: newpeval: check if isAll() is all (contains("_all" or "*"))
        if (requestedResolved.isAll()
                && WildcardMatcher.matchAny(securityDeniedActionPatterns, action)) {
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
