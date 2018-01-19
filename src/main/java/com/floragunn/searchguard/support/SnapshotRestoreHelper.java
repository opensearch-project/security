/*
 * Copyright 2015-2017 floragunn GmbH
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

package com.floragunn.searchguard.support;

import java.util.List;
import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.repositories.Repository;
import org.elasticsearch.snapshots.SnapshotId;
import org.elasticsearch.snapshots.SnapshotInfo;
import org.elasticsearch.snapshots.SnapshotUtils;

import com.floragunn.searchguard.SearchGuardPlugin;

public class SnapshotRestoreHelper {

    protected static final Logger log = LogManager.getLogger(SnapshotRestoreHelper.class);
    
    public static List<String> resolveOriginalIndices(RestoreSnapshotRequest restoreRequest) {
        
        final RepositoriesService repositoriesService = Objects.requireNonNull(SearchGuardPlugin.GuiceHolder.getRepositoriesService(), "RepositoriesService not initialized");     
        //hack, because it seems not possible to access RepositoriesService from a non guice class
        final Repository repository = repositoriesService.repository(restoreRequest.repository());
        SnapshotInfo snapshotInfo = null;

        for (final SnapshotId snapshotId : repository.getRepositoryData().getSnapshotIds()) {
            if (snapshotId.getName().equals(restoreRequest.snapshot())) {

                if(log.isDebugEnabled()) {
                    log.debug("snapshot found: {} (UUID: {})", snapshotId.getName(), snapshotId.getUUID());    
                }

                snapshotInfo = repository.getSnapshotInfo(snapshotId);
                break;
            }
        }

        if (snapshotInfo == null) {
            log.warn("snapshot repository '" + restoreRequest.repository() + "', snapshot '" + restoreRequest.snapshot() + "' not found");
            return null;
        } else {
            return SnapshotUtils.filterIndices(snapshotInfo.indices(), restoreRequest.indices(), restoreRequest.indicesOptions());
        }    

        
    }
    
}
