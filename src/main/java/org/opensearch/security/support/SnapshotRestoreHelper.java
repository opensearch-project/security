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

package org.opensearch.security.support;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.Objects;

import org.opensearch.security.OpenSearchSecurityPlugin;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.SpecialPermission;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.repositories.Repository;
import org.opensearch.snapshots.SnapshotId;
import org.opensearch.snapshots.SnapshotInfo;
import org.opensearch.snapshots.SnapshotUtils;
import org.opensearch.threadpool.ThreadPool;

public class SnapshotRestoreHelper {

    protected static final Logger log = LoggerFactory.getLogger(SnapshotRestoreHelper.class);
    
    public static List<String> resolveOriginalIndices(RestoreSnapshotRequest restoreRequest) {
        final SnapshotInfo snapshotInfo = getSnapshotInfo(restoreRequest);

        if (snapshotInfo == null) {
            log.warn("snapshot repository '{}', snapshot '{}' not found", restoreRequest.repository(), restoreRequest.snapshot());
            return null;
        } else {
            return SnapshotUtils.filterIndices(snapshotInfo.indices(), restoreRequest.indices(), restoreRequest.indicesOptions());
        }    
        
        
    }
    
    public static SnapshotInfo getSnapshotInfo(RestoreSnapshotRequest restoreRequest) {
        final RepositoriesService repositoriesService = Objects.requireNonNull(OpenSearchSecurityPlugin.GuiceHolder.getRepositoriesService(), "RepositoriesService not initialized");
        final Repository repository = repositoriesService.repository(restoreRequest.repository());
        final String threadName = Thread.currentThread().getName();
        SnapshotInfo snapshotInfo = null;
        
        try {
            setCurrentThreadName("[" + ThreadPool.Names.GENERIC + "]");
            for (SnapshotId snapshotId : PlainActionFuture.get(repository::getRepositoryData).getSnapshotIds()) {
                if (snapshotId.getName().equals(restoreRequest.snapshot())) {

                    if(log.isDebugEnabled()) {
                        log.debug("snapshot found: {} (UUID: {})", snapshotId.getName(), snapshotId.getUUID());
                    }

                    snapshotInfo = repository.getSnapshotInfo(snapshotId);
                    break;
                }
            }
        } finally {
            setCurrentThreadName(threadName);
        }
        return snapshotInfo;
    }
    
    private static void setCurrentThreadName(final String name) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                Thread.currentThread().setName(name);
                return null;
            }
        });
    }
    
}
