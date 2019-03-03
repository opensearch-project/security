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

package com.amazon.opendistroforelasticsearch.security;

import java.util.Arrays;
import java.util.Collection;

import org.apache.http.HttpStatus;
import org.elasticsearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.elasticsearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateAction;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateRequest;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateResponse;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;

@RunWith(Parameterized.class)
public class SnapshotRestoreTests extends SingleClusterTest {

    @Parameters
    public static Collection<ClusterConfiguration> data() {
        return Arrays.asList(new ClusterConfiguration[] {     
                ClusterConfiguration.DEFAULT
           });
    }
    
    @Parameter
    public ClusterConfiguration currentClusterConfig;

    @Test
    public void testSnapshotEnableSecurityIndexRestore() throws Exception {
    
        final Settings settings = Settings.builder()
                .putList("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .put("opendistro_security.enable_snapshot_restore_privilege", true)
                .put("opendistro_security.check_snapshot_restore_write_privileges", false)
                .put("opendistro_security.unsupported.restore.securityindex.enabled", true)
                .build();
    
        setup(settings, currentClusterConfig);
    
        try (TransportClient tc = getInternalTransportClient()) {    
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                
            tc.admin().cluster().putRepository(new PutRepositoryRequest("vulcangov").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/vulcangov"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("vulcangov", "vulcangov_1").indices("vulcangov").includeGlobalState(true).waitForCompletion(true)).actionGet();
    
            tc.admin().cluster().putRepository(new PutRepositoryRequest(".opendistro_security").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/.opendistro_security"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest(".opendistro_security", "opendistro_security_1").indices(".opendistro_security").includeGlobalState(false).waitForCompletion(true)).actionGet();
    
            tc.admin().cluster().putRepository(new PutRepositoryRequest("all").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("all", "all_1").indices("*").includeGlobalState(false).waitForCompletion(true)).actionGet();
        }
    
        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov/vulcangov_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // worf not allowed to restore vulcangov index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","", encodeBasicHeader("worf", "worf")).getStatusCode());
        // Try to restore vulcangov index as .opendistro_security index, not possible since Security index is open
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore .opendistro_security index.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/.opendistro_security", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/.opendistro_security/opendistro_security_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // 500 because Security index is open
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, rh.executePostRequest("_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true","{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore all indices.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all/all_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // 500 because Security index is open
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore vulcangov index as .opendistro_security index -> 500 because Security index is open
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore .opendistro_security index as .opendistro_security_copy index. Delete opendistro_security_copy first, was created in test above
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeDeleteRequest("opendistro_security_copy", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore a unknown snapshot
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, rh.executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true", "", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        
        // close and restore Security index
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest(".opendistro_security/_close", "", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest(".opendistro_security/_open", "", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    }
    
    @Test
    public void testSnapshot() throws Exception {
    
        final Settings settings = Settings.builder()
                .putList("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .put("opendistro_security.enable_snapshot_restore_privilege", true)
                .put("opendistro_security.check_snapshot_restore_write_privileges", false)
                .build();
    
        setup(settings, currentClusterConfig);
    
        try (TransportClient tc = getInternalTransportClient()) {    
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                
            tc.admin().cluster().putRepository(new PutRepositoryRequest("vulcangov").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/vulcangov"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("vulcangov", "vulcangov_1").indices("vulcangov").includeGlobalState(true).waitForCompletion(true)).actionGet();
    
            tc.admin().cluster().putRepository(new PutRepositoryRequest(".opendistro_security").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/.opendistro_security"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest(".opendistro_security", "opendistro_security_1").indices(".opendistro_security").includeGlobalState(false).waitForCompletion(true)).actionGet();
    
            tc.admin().cluster().putRepository(new PutRepositoryRequest("all").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("all", "all_1").indices("*").includeGlobalState(false).waitForCompletion(true)).actionGet();
        }
    
        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov/vulcangov_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","", encodeBasicHeader("worf", "worf")).getStatusCode());
        // Try to restore vulcangov index as .opendistro_security index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore .opendistro_security index.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/.opendistro_security", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/.opendistro_security/opendistro_security_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true","{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore all indices.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all/all_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore a unknown snapshot
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true", "", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true","{ \"indices\": \"the-unknown-index\" }", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
    }

    @Test
    public void testSnapshotCheckWritePrivileges() throws Exception {
    
        final Settings settings = Settings.builder()
                .putList("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .put("opendistro_security.enable_snapshot_restore_privilege", true)
                .put("opendistro_security.check_snapshot_restore_write_privileges", true)
                .build();
    
        setup(settings, currentClusterConfig);
    
        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            
            tc.admin().cluster().putRepository(new PutRepositoryRequest("vulcangov").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/vulcangov"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("vulcangov", "vulcangov_1").indices("vulcangov").includeGlobalState(true).waitForCompletion(true)).actionGet();
    
            tc.admin().cluster().putRepository(new PutRepositoryRequest(".opendistro_security").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/.opendistro_security"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest(".opendistro_security", "opendistro_security_1").indices(".opendistro_security").includeGlobalState(false).waitForCompletion(true)).actionGet();
    
            tc.admin().cluster().putRepository(new PutRepositoryRequest("all").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("all", "all_1").indices("*").includeGlobalState(false).waitForCompletion(true)).actionGet();
    
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(currentClusterConfig.getNodes(), cur.getNodes().size());
            System.out.println(cur.getNodesMap());
        }
    
        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov/vulcangov_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","", encodeBasicHeader("worf", "worf")).getStatusCode());
        // Try to restore vulcangov index as .opendistro_security index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore .opendistro_security index.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/.opendistro_security", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/.opendistro_security/opendistro_security_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/.opendistro_security/opendistro_security_1/_restore?wait_for_completion=true","{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore all indices.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all/all_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \".opendistro_security\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore .opendistro_security index as .opendistro_security_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \".opendistro_security\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"opendistro_security_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore a unknown snapshot
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true", "", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Tests snapshot with write permissions (OK)
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_restore_1\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_restore_2a\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
    
        // Test snapshot with write permissions (FAIL)
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_1\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_2\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_3\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_4\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
    }

    @Test
    public void testSnapshotRestore() throws Exception {
    
        final Settings settings = Settings.builder()
                .putList("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .put("opendistro_security.enable_snapshot_restore_privilege", true)
                .put("opendistro_security.check_snapshot_restore_write_privileges", true)
                .build();
    
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityActionGroups("action_groups_packaged.yml"), settings, true, currentClusterConfig);
    
        try (TransportClient tc = getInternalTransportClient()) {    
            tc.index(new IndexRequest("testsnap1").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap2").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap3").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap4").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap5").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap6").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            
            tc.admin().cluster().putRepository(new PutRepositoryRequest("bckrepo").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/bckrepo"))).actionGet();
        }
    
        RestHelper rh = nonSslRestHelper();        
        String putSnapshot =
        "{"+
          "\"indices\": \"testsnap1\","+
          "\"ignore_unavailable\": false,"+
          "\"include_global_state\": false"+
        "}";
        
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"?wait_for_completion=true&pretty", putSnapshot, encodeBasicHeader("snapresuser", "nagilum")).getStatusCode()); 
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"/_restore?wait_for_completion=true&pretty","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("snapresuser", "nagilum")).getStatusCode());
        
        putSnapshot =
        "{"+
          "\"indices\": \".opendistro_security\","+
          "\"ignore_unavailable\": false,"+
          "\"include_global_state\": false"+
        "}";
                
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"?wait_for_completion=true&pretty", putSnapshot, encodeBasicHeader("snapresuser", "nagilum")).getStatusCode()); 
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"/_restore?wait_for_completion=true&pretty","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("snapresuser", "nagilum")).getStatusCode());
              
        putSnapshot =
        "{"+
          "\"indices\": \"testsnap2\","+
          "\"ignore_unavailable\": false,"+
          "\"include_global_state\": true"+
        "}";
                        
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"?wait_for_completion=true&pretty", putSnapshot, encodeBasicHeader("snapresuser", "nagilum")).getStatusCode()); 
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"/_restore?wait_for_completion=true&pretty","{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("snapresuser", "nagilum")).getStatusCode());
    }

}
