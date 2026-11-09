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

package org.opensearch.security.privileges.actionlevel.legacy;

import org.junit.Test;

import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotAction;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.NullAuditLog;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class SnapshotRestoreEvaluatorTest {

    @Test
    public void evaluate_notClusterManager_deferredToClusterManager() {
        SnapshotRestoreEvaluator subject = new SnapshotRestoreEvaluator(Settings.EMPTY, new NullAuditLog(), () -> false);

        PrivilegesEvaluatorResponse response = subject.evaluate(
            new RestoreSnapshotRequest("repository", "snapshot"),
            null,
            RestoreSnapshotAction.NAME
        );

        assertThat(response.isAllowed(), is(true));
        assertThat(response.isDeferredToClusterManager(), is(true));
    }

    @Test
    public void evaluate_clusterManager_decidedLocally() {
        SnapshotRestoreEvaluator subject = new SnapshotRestoreEvaluator(Settings.EMPTY, new NullAuditLog(), () -> true);

        PrivilegesEvaluatorResponse response = subject.evaluate(
            new RestoreSnapshotRequest("repository", "snapshot").includeGlobalState(true),
            null,
            RestoreSnapshotAction.NAME
        );

        assertThat(response.isAllowed(), is(false));
        assertThat(response.isDeferredToClusterManager(), is(false));
    }
}
