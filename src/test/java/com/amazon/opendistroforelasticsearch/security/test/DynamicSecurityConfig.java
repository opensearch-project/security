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

package com.amazon.opendistroforelasticsearch.security.test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;

public class DynamicSecurityConfig {
    
    private String securityIndexName = ".opendistro_security";
    private String securityConfig = "config.yml";
    private String securityRoles = "roles.yml";
    private String securityRolesMapping = "roles_mapping.yml";
    private String securityInternalUsers = "internal_users.yml";
    private String securityActionGroups = "action_groups.yml";
    private String securityConfigAsYamlString = null;

    public String getSecurityIndexName() {
        return securityIndexName;
    }
    public DynamicSecurityConfig setSecurityIndexName(String securityIndexName) {
        this.securityIndexName = securityIndexName;
        return this;
    }

    public DynamicSecurityConfig setConfig(String securityConfig) {
        this.securityConfig = securityConfig;
        return this;
    }

    public DynamicSecurityConfig setConfigAsYamlString(String securityConfigAsYamlString) {
        this.securityConfigAsYamlString = securityConfigAsYamlString;
        return this;
    }

    public DynamicSecurityConfig setSecurityRoles(String securityRoles) {
        this.securityRoles = securityRoles;
        return this;
    }

    public DynamicSecurityConfig setSecurityRolesMapping(String securityRolesMapping) {
        this.securityRolesMapping = securityRolesMapping;
        return this;
    }

    public DynamicSecurityConfig setSecurityInternalUsers(String securityInternalUsers) {
        this.securityInternalUsers = securityInternalUsers;
        return this;
    }

    public DynamicSecurityConfig setSecurityActionGroups(String securityActionGroups) {
        this.securityActionGroups = securityActionGroups;
        return this;
    }
    
    public List<IndexRequest> getDynamicConfig(String folder) {
        
        final String prefix = folder == null?"":folder+"/";
        
        List<IndexRequest> ret = new ArrayList<IndexRequest>();
        
        ret.add(new IndexRequest(securityIndexName)
               .type("security")
               .id(ConfigConstants.CONFIGNAME_CONFIG)
               .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
               .source(ConfigConstants.CONFIGNAME_CONFIG, securityConfigAsYamlString==null?FileHelper.readYamlContent(prefix+securityConfig):FileHelper.readYamlContentFromString(securityConfigAsYamlString)));
        
        ret.add(new IndexRequest(securityIndexName)
        .type("security")
        .id(ConfigConstants.CONFIGNAME_ACTION_GROUPS)
        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        .source(ConfigConstants.CONFIGNAME_ACTION_GROUPS, FileHelper.readYamlContent(prefix+securityActionGroups)));
 
        ret.add(new IndexRequest(securityIndexName)
        .type("security")
        .id(ConfigConstants.CONFIGNAME_INTERNAL_USERS)
        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        .source(ConfigConstants.CONFIGNAME_INTERNAL_USERS, FileHelper.readYamlContent(prefix+securityInternalUsers)));
 
        ret.add(new IndexRequest(securityIndexName)
        .type("security")
        .id(ConfigConstants.CONFIGNAME_ROLES)
        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        .source(ConfigConstants.CONFIGNAME_ROLES, FileHelper.readYamlContent(prefix+securityRoles)));
 
        ret.add(new IndexRequest(securityIndexName)
        .type("security")
        .id(ConfigConstants.CONFIGNAME_ROLES_MAPPING)
        .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        .source(ConfigConstants.CONFIGNAME_ROLES_MAPPING, FileHelper.readYamlContent(prefix+securityRolesMapping)));
 
        
        return Collections.unmodifiableList(ret);
    }

}
