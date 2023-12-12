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

package org.opensearch.security;

import java.util.Arrays;
import java.util.List;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.opensearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

public class SnapshotRestoreTests extends SingleClusterTest {
    private ClusterConfiguration currentClusterConfig = ClusterConfiguration.DEFAULT;

    @Test
    public void testSnapshotEnableSecurityIndexRestore() throws Exception {

        final Settings settings = Settings.builder()
            .putList("path.repo", repositoryPath.getRoot().getAbsolutePath())
            .put("plugins.security.check_snapshot_restore_write_privileges", false)
            .put("plugins.security.unsupported.restore.securityindex.enabled", true)
            .build();

        setup(settings, currentClusterConfig);

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest("vulcangov").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/vulcangov"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(
                    new CreateSnapshotRequest("vulcangov", "vulcangov_1").indices("vulcangov")
                        .includeGlobalState(true)
                        .waitForCompletion(true)
                )
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest(".opendistro_security").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/.opendistro_security"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(
                    new CreateSnapshotRequest(".opendistro_security", "opendistro_security_1").indices(".opendistro_security")
                        .includeGlobalState(false)
                        .waitForCompletion(true)
                )
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest("all").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(new CreateSnapshotRequest("all", "all_1").indices("*").includeGlobalState(false).waitForCompletion(true))
                .actionGet();
        }

        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/vulcangov", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/vulcangov/vulcangov_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        // worf not allowed to restore vulcangov index
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("worf", "worf")
            ).getStatusCode()
        );
        // Try to restore vulcangov index as .opendistro_security index, not possible since Security index is open
        Assert.assertEquals(
            HttpStatus.SC_INTERNAL_SERVER_ERROR,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Try to restore .opendistro_security index.
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/.opendistro_security", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/.opendistro_security/opendistro_security_1", encodeBasicHeader("nagilum", "nagilum"))
                .getStatusCode()
        );
        // 500 because Security index is open
        Assert.assertEquals(
            HttpStatus.SC_INTERNAL_SERVER_ERROR,
            rh.executePostRequest(
                "_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true",
                "{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Try to restore all indices.
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/all", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/all/all_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        // 500 because Security index is open
        Assert.assertEquals(
            HttpStatus.SC_INTERNAL_SERVER_ERROR,
            rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true", "", encodeBasicHeader("nagilum", "nagilum"))
                .getStatusCode()
        );
        // Try to restore vulcangov index as .opendistro_security index -> 500 because Security index is open
        Assert.assertEquals(
            HttpStatus.SC_INTERNAL_SERVER_ERROR,
            rh.executePostRequest(
                "_snapshot/all/all_1/_restore?wait_for_completion=true",
                "{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        // Try to restore .opendistro_security index as .opendistro_security_copy index. Delete opendistro_security_copy first, was created
        // in test above
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeDeleteRequest("opendistro_security_copy", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/all/all_1/_restore?wait_for_completion=true",
                "{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Try to restore an unknown snapshot
        Assert.assertEquals(
            HttpStatus.SC_INTERNAL_SERVER_ERROR,
            rh.executePostRequest(
                "_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // close and restore Security index
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(".opendistro_security/_close", "", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(".opendistro_security/_open", "", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
    }

    @Test
    public void testSnapshot() throws Exception {

        final Settings settings = Settings.builder()
            .putList("path.repo", repositoryPath.getRoot().getAbsolutePath())
            .put("plugins.security.check_snapshot_restore_write_privileges", false)
            .build();

        setup(settings, currentClusterConfig);

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest("vulcangov").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/vulcangov"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(
                    new CreateSnapshotRequest("vulcangov", "vulcangov_1").indices("vulcangov")
                        .includeGlobalState(true)
                        .waitForCompletion(true)
                )
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest(".opendistro_security").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/.opendistro_security"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(
                    new CreateSnapshotRequest(".opendistro_security", "opendistro_security_1").indices(".opendistro_security")
                        .includeGlobalState(false)
                        .waitForCompletion(true)
                )
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest("all").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(new CreateSnapshotRequest("all", "all_1").indices("*").includeGlobalState(false).waitForCompletion(true))
                .actionGet();
        }

        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/vulcangov", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/vulcangov/vulcangov_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("worf", "worf")
            ).getStatusCode()
        );
        // Try to restore vulcangov index as .opendistro_security index
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Try to restore .opendistro_security index.
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/.opendistro_security", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/.opendistro_security/opendistro_security_1", encodeBasicHeader("nagilum", "nagilum"))
                .getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true",
                "{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Try to restore all indices.
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/all", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/all/all_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true", "", encodeBasicHeader("nagilum", "nagilum"))
                .getStatusCode()
        );
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/all/all_1/_restore?wait_for_completion=true",
                "{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/all/all_1/_restore?wait_for_completion=true",
                "{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Try to restore an unknown snapshot
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        // Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
        // executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true","{ \"indices\": \"the-unknown-index\" }",
        // encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
    }

    @Test
    public void testSnapshotCheckWritePrivileges() throws Exception {

        final Settings settings = Settings.builder().putList("path.repo", repositoryPath.getRoot().getAbsolutePath()).build();

        setup(settings, currentClusterConfig);

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("vulcangov").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest("vulcangov").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/vulcangov"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(
                    new CreateSnapshotRequest("vulcangov", "vulcangov_1").indices("vulcangov")
                        .includeGlobalState(true)
                        .waitForCompletion(true)
                )
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest(".opendistro_security").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/.opendistro_security"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(
                    new CreateSnapshotRequest(".opendistro_security", "opendistro_security_1").indices(".opendistro_security")
                        .includeGlobalState(false)
                        .waitForCompletion(true)
                )
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest("all").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(new CreateSnapshotRequest("all", "all_1").indices("*").includeGlobalState(false).waitForCompletion(true))
                .actionGet();

            ConfigUpdateResponse cur = tc.execute(
                ConfigUpdateAction.INSTANCE,
                new ConfigUpdateRequest(new String[] { "config", "roles", "rolesmapping", "internalusers", "actiongroups" })
            ).actionGet();
            Assert.assertFalse(cur.hasFailures());
            Assert.assertEquals(currentClusterConfig.getNodes(), cur.getNodes().size());
        }

        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/vulcangov", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/vulcangov/vulcangov_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("worf", "worf")
            ).getStatusCode()
        );
        // Try to restore vulcangov index as .opendistro_security index
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Try to restore .opendistro_security index.
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/.opendistro_security", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/.opendistro_security/opendistro_security_1", encodeBasicHeader("nagilum", "nagilum"))
                .getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true",
                "{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Try to restore all indices.
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/all", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_snapshot/all/all_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true", "", encodeBasicHeader("nagilum", "nagilum"))
                .getStatusCode()
        );
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/all/all_1/_restore?wait_for_completion=true",
                "{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/all/all_1/_restore?wait_for_completion=true",
                "{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Try to restore an unknown snapshot
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true",
                "",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );

        // Tests snapshot with write permissions (OK)
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_restore_1\" }",
                encodeBasicHeader("restoreuser", "restoreuser")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_restore_2a\" }",
                encodeBasicHeader("restoreuser", "restoreuser")
            ).getStatusCode()
        );

        // Test snapshot with write permissions (OK)
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_1\" }",
                encodeBasicHeader("restoreuser", "restoreuser")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_2\" }",
                encodeBasicHeader("restoreuser", "restoreuser")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_3\" }",
                encodeBasicHeader("restoreuser", "restoreuser")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_4\" }",
                encodeBasicHeader("restoreuser", "restoreuser")
            ).getStatusCode()
        );
    }

    @Test
    public void testSnapshotRestore() throws Exception {

        final Settings settings = Settings.builder().putList("path.repo", repositoryPath.getRoot().getAbsolutePath()).build();

        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setSecurityActionGroups("action_groups_packaged.yml"),
            settings,
            true,
            currentClusterConfig
        );

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("testsnap1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap3").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap4").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap5").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap6").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest("bckrepo").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/bckrepo"))
                )
                .actionGet();
        }

        RestHelper rh = nonSslRestHelper();
        String putSnapshot = "{"
            + "\"indices\": \"testsnap1\","
            + "\"ignore_unavailable\": false,"
            + "\"include_global_state\": false"
            + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePutRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "?wait_for_completion=true&pretty",
                putSnapshot,
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "/_restore?wait_for_completion=true&pretty",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }",
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );

        putSnapshot = "{"
            + "\"indices\": \".opendistro_security\","
            + "\"ignore_unavailable\": false,"
            + "\"include_global_state\": false"
            + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePutRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "?wait_for_completion=true&pretty",
                putSnapshot,
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "/_restore?wait_for_completion=true&pretty",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }",
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );

        putSnapshot = "{" + "\"indices\": \"testsnap2\"," + "\"ignore_unavailable\": false," + "\"include_global_state\": true" + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePutRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "?wait_for_completion=true&pretty",
                putSnapshot,
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "/_restore?wait_for_completion=true&pretty",
                "{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }",
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );
    }

    @Test
    public void testSnapshotRestoreSpecialIndicesPatterns() throws Exception {
        // Run with ./gradlew test --tests org.opensearch.security.SnapshotRestoreTests.testSnapshotRestoreSpecialIndicesPatterns

        final List<String> listOfIndexesToTest = Arrays.asList("foo", "bar", "baz");

        final Settings settings = Settings.builder().putList("path.repo", repositoryPath.getRoot().getAbsolutePath()).build();

        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setSecurityActionGroups("action_groups_packaged.yml"),
            settings,
            true,
            currentClusterConfig
        );

        try (Client tc = getClient()) {
            for (String index : listOfIndexesToTest) {
                tc.admin().indices().create(new CreateIndexRequest(index)).actionGet();
                tc.index(
                    new IndexRequest(index).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .id("document1")
                        .source("{ \"foo\": \"bar\" }", XContentType.JSON)
                ).actionGet();
            }
        }

        try (Client tc = getClient()) {
            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest("all").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))
                )
                .actionGet();
            tc.admin()
                .cluster()
                .createSnapshot(
                    new CreateSnapshotRequest("all", "all_1").indices(listOfIndexesToTest).includeGlobalState(false).waitForCompletion(true)
                )
                .actionGet();
        }

        RestHelper rh = nonSslRestHelper();

        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/all/all_1/_restore?wait_for_completion=true",
                "{\"indices\": \"b*,-bar\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"wild_first_restored_index_$1\"}",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePostRequest(
                "_snapshot/all/all_1/_restore?wait_for_completion=true",
                "{\"indices\": \"-bar,b*\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"neg_first_restored_index_$1\"}",
                encodeBasicHeader("nagilum", "nagilum")
            ).getStatusCode()
        );
        String wild_first_body = rh.executePostRequest(
            "_snapshot/all/all_1/_restore?wait_for_completion=true",
            "{\"indices\": \"b*,-bar\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"wild_first_restored_index_$1\"}",
            encodeBasicHeader("nagilum", "nagilum")
        ).getBody();
        assertThat(wild_first_body, not(containsString("wild_first_restored_index_foo")));
        assertThat(wild_first_body, not(containsString("wild_first_restored_index_bar")));
        assertThat(wild_first_body, containsString("wild_first_restored_index_baz"));
        String neg_first_body = rh.executePostRequest(
            "_snapshot/all/all_1/_restore?wait_for_completion=true",
            "{\"indices\": \"-bar,b*\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"negate_first_restored_index_$1\"}",
            encodeBasicHeader("nagilum", "nagilum")
        ).getBody();
        assertThat(neg_first_body, not(containsString("negate_first_restored_index_foo")));
        assertThat(neg_first_body, not(containsString("negate_first_restored_index_bar")));
        assertThat(neg_first_body, containsString("negate_first_restored_index_baz"));
    }

    @Test
    public void testNoSnapshotRestore() throws Exception {

        final Settings settings = Settings.builder()
            .putList("path.repo", repositoryPath.getRoot().getAbsolutePath())
            .put("plugins.security.enable_snapshot_restore_privilege", false)
            .build();

        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setSecurityActionGroups("action_groups_packaged.yml"),
            settings,
            true,
            currentClusterConfig
        );

        try (Client tc = getClient()) {
            tc.index(new IndexRequest("testsnap1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap3").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap4").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap5").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();
            tc.index(new IndexRequest("testsnap6").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON))
                .actionGet();

            tc.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest("bckrepo").type("fs")
                        .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/bckrepo"))
                )
                .actionGet();
        }

        RestHelper rh = nonSslRestHelper();
        String putSnapshot = "{"
            + "\"indices\": \"testsnap1\","
            + "\"ignore_unavailable\": false,"
            + "\"include_global_state\": false"
            + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePutRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "?wait_for_completion=true&pretty",
                putSnapshot,
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "/_restore?wait_for_completion=true&pretty",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }",
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );

        putSnapshot = "{"
            + "\"indices\": \".opendistro_security\","
            + "\"ignore_unavailable\": false,"
            + "\"include_global_state\": false"
            + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePutRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "?wait_for_completion=true&pretty",
                putSnapshot,
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "/_restore?wait_for_completion=true&pretty",
                "{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }",
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );

        putSnapshot = "{" + "\"indices\": \"testsnap2\"," + "\"ignore_unavailable\": false," + "\"include_global_state\": true" + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePutRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "?wait_for_completion=true&pretty",
                putSnapshot,
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_FORBIDDEN,
            rh.executePostRequest(
                "_snapshot/bckrepo/" + putSnapshot.hashCode() + "/_restore?wait_for_completion=true&pretty",
                "{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }",
                encodeBasicHeader("snapresuser", "nagilum")
            ).getStatusCode()
        );
    }
}
