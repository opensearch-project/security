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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.privileges;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.tasks.Task;

import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SnapshotRestoreHelper;

public class SnapshotRestoreEvaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final boolean enableSnapshotRestorePrivilege;
    private final String securityIndex;
    private final AuditLog auditLog;
    private final boolean restoreSecurityIndexEnabled;
    
    public SnapshotRestoreEvaluator(final Settings settings, AuditLog auditLog) {
        this.enableSnapshotRestorePrivilege = settings.getAsBoolean(ConfigConstants.SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
                ConfigConstants.SECURITY_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE);
        this.restoreSecurityIndexEnabled = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED, false);

        this.securityIndex = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.auditLog = auditLog;
    }

    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final Task task, final String action, final ClusterInfoHolder clusterInfoHolder,
            final PrivilegesEvaluatorResponse presponse) {

        if (!(request instanceof RestoreSnapshotRequest)) {
            return presponse;
        }
        
        // snapshot restore for regular users not enabled
        if (!enableSnapshotRestorePrivilege) {
            log.warn("{} is not allowed for a regular user", action);
            presponse.allowed = false;
            return presponse.markComplete();            
        }

        // if this feature is enabled, users can also snapshot and restore
        // the Security index and the global state
        if (restoreSecurityIndexEnabled) {
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
            auditLog.logSecurityIndexAttempt(request, action, task);
            log.warn("{} with 'include_global_state' enabled is not allowed", action);
            presponse.allowed = false;
            return presponse.markComplete();            
        }

        final List<String> rs = SnapshotRestoreHelper.resolveOriginalIndices(restoreRequest);

        if (rs != null && (rs.contains(securityIndex) || rs.contains("_all") || rs.contains("*"))) {
            auditLog.logSecurityIndexAttempt(request, action, task);
            log.warn("{} for '{}' as source index is not allowed", action, securityIndex);
            presponse.allowed = false;
            return presponse.markComplete();            
        }
        return presponse;
    }
}
