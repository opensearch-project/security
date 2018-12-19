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

package com.floragunn.searchguard.test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.helper.file.FileHelper;

public class DynamicSgConfig {
    
    private String searchGuardIndexName = "searchguard";
    private String sgConfig = "sg_config.yml";
    private String sgRoles = "sg_roles.yml";
    private String sgRolesMapping = "sg_roles_mapping.yml";
    private String sgInternalUsers = "sg_internal_users.yml";
    private String sgActionGroups = "sg_action_groups.yml";
    private String sgConfigAsYamlString = null;

    public String getSearchGuardIndexName() {
        return searchGuardIndexName;
    }
    public DynamicSgConfig setSearchGuardIndexName(String searchGuardIndexName) {
        this.searchGuardIndexName = searchGuardIndexName;
        return this;
    }

    public DynamicSgConfig setSgConfig(String sgConfig) {
        this.sgConfig = sgConfig;
        return this;
    }

    public DynamicSgConfig setSgConfigAsYamlString(String sgConfigAsYamlString) {
        this.sgConfigAsYamlString = sgConfigAsYamlString;
        return this;
    }

    public DynamicSgConfig setSgRoles(String sgRoles) {
        this.sgRoles = sgRoles;
        return this;
    }

    public DynamicSgConfig setSgRolesMapping(String sgRolesMapping) {
        this.sgRolesMapping = sgRolesMapping;
        return this;
    }

    public DynamicSgConfig setSgInternalUsers(String sgInternalUsers) {
        this.sgInternalUsers = sgInternalUsers;
        return this;
    }

    public DynamicSgConfig setSgActionGroups(String sgActionGroups) {
        this.sgActionGroups = sgActionGroups;
        return this;
    }
    
    public List<IndexRequest> getDynamicConfig(String folder) {
        
        final String prefix = folder == null?"":folder+"/";
        
        List<IndexRequest> ret = new ArrayList<IndexRequest>();
        
        ret.add(new IndexRequest(searchGuardIndexName)
               .type("sg")
               .id(ConfigConstants.CONFIGNAME_CONFIG)
               .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
               .source(ConfigConstants.CONFIGNAME_CONFIG, sgConfigAsYamlString==null?FileHelper.readYamlContent(prefix+sgConfig):FileHelper.readYamlContentFromString(sgConfigAsYamlString)));
        
        ret.add(new IndexRequest(searchGuardIndexName)
        .type("sg")
        .id(ConfigConstants.CONFIGNAME_ACTION_GROUPS)
        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        .source(ConfigConstants.CONFIGNAME_ACTION_GROUPS, FileHelper.readYamlContent(prefix+sgActionGroups)));
 
        ret.add(new IndexRequest(searchGuardIndexName)
        .type("sg")
        .id(ConfigConstants.CONFIGNAME_INTERNAL_USERS)
        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        .source(ConfigConstants.CONFIGNAME_INTERNAL_USERS, FileHelper.readYamlContent(prefix+sgInternalUsers)));
 
        ret.add(new IndexRequest(searchGuardIndexName)
        .type("sg")
        .id(ConfigConstants.CONFIGNAME_ROLES)
        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        .source(ConfigConstants.CONFIGNAME_ROLES, FileHelper.readYamlContent(prefix+sgRoles)));
 
        ret.add(new IndexRequest(searchGuardIndexName)
        .type("sg")
        .id(ConfigConstants.CONFIGNAME_ROLES_MAPPING)
        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        .source(ConfigConstants.CONFIGNAME_ROLES_MAPPING, FileHelper.readYamlContent(prefix+sgRolesMapping)));
 
        
        return Collections.unmodifiableList(ret);
    }

}
