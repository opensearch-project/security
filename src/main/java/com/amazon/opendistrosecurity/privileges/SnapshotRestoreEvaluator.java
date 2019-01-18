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
package com.amazon.opendistrosecurity.privileges;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;

import com.amazon.opendistrosecurity.auditlog.AuditLog;
import com.amazon.opendistrosecurity.configuration.ClusterInfoHolder;
import com.amazon.opendistrosecurity.support.ConfigConstants;
import com.amazon.opendistrosecurity.support.SnapshotRestoreHelper;

public class SnapshotRestoreEvaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final boolean enableSnapshotRestorePrivilege;
    private final String opendistrosecurityIndex;
    private final AuditLog auditLog;
    private final boolean restoreSgIndexEnabled;
    
    public SnapshotRestoreEvaluator(final Settings settings, AuditLog auditLog) {
        this.enableSnapshotRestorePrivilege = settings.getAsBoolean(ConfigConstants.OPENDISTROSECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
                ConfigConstants.SG_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE);
        this.restoreSgIndexEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTROSECURITY_UNSUPPORTED_RESTORE_SGINDEX_ENABLED, false);

        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTROSECURITY_CONFIG_INDEX_NAME, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        this.auditLog = auditLog;
    }

    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final Task task, final String action, final ClusterInfoHolder clusterInfoHolder,
            final PrivilegesEvaluatorResponse presponse) {

        if (!(request instanceof RestoreSnapshotRequest)) {
            return presponse;
        }
        
        // snapshot restore for regular users not enabled
        if (!enableSnapshotRestorePrivilege) {
            log.warn(action + " is not allowed for a regular user");
            presponse.allowed = false;
            return presponse.markComplete();            
        }

        // if this feature is enabled, users can also snapshot and restore
        // the SG index and the global state
        if (restoreSgIndexEnabled) {
            presponse.allowed = true;
            return presponse;            
        }

        
        if (clusterInfoHolder.isLocalNodeElectedMaster() == Boolean.FALSE) {
            presponse.allowed = true;
            return presponse.markComplete();            
        }
        
        final RestoreSnapshotRequest restoreRequest = (RestoreSnapshotRequest) request;

        // Do not allow restore of global state
        if (restoreRequest.includeGlobalState()) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " with 'include_global_state' enabled is not allowed");
            presponse.allowed = false;
            return presponse.markComplete();            
        }

        final List<String> rs = SnapshotRestoreHelper.resolveOriginalIndices(restoreRequest);

        if (rs != null && (rs.contains(opendistrosecurityIndex) || rs.contains("_all") || rs.contains("*"))) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " for '{}' as source index is not allowed", opendistrosecurityIndex);
            presponse.allowed = false;
            return presponse.markComplete();            
        }
        return presponse;
    }
}
