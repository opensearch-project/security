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

package org.opensearch.security.test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;

import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.test.helper.file.FileHelper;

public class DynamicSecurityConfig {

    private String securityIndexName = ".opendistro_security";
    private String securityConfig = "config.yml";
    private String securityRoles = "roles.yml";
    private String securityTenants = "roles_tenants.yml";
    private String securityRolesMapping = "roles_mapping.yml";
    private String securityInternalUsers = "internal_users.yml";
    private String securityActionGroups = "action_groups.yml";
    private String securityNodesDn = "nodes_dn.yml";
    private String securityWhitelist= "whitelist.yml";
    private String securityAudit = "audit.yml";
    private String securityConfigAsYamlString = null;
    private String type = "_doc";
    private String legacyConfigFolder = "";

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

    public DynamicSecurityConfig setSecurityNodesDn(String nodesDn) {
        this.securityNodesDn = nodesDn;
        return this;
    }

    public DynamicSecurityConfig setSecurityWhitelist(String whitelist){
        this.securityWhitelist = whitelist;
        return this;
    }

    public DynamicSecurityConfig setSecurityAudit(String audit) {
        this.securityAudit = audit;
        return this;
    }

    public DynamicSecurityConfig setLegacy() {
        this.type = "security";
        this.legacyConfigFolder = "legacy/securityconfig_v6/";
        return this;
    }
    public String getType() {
        return type;
    }

    public List<IndexRequest> getDynamicConfig(String folder) {

        final String prefix = legacyConfigFolder+(folder == null?"":folder+"/");

        List<IndexRequest> ret = new ArrayList<IndexRequest>();

        ret.add(new IndexRequest(securityIndexName)
                .type(type)
                .id(CType.CONFIG.toLCString())
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(CType.CONFIG.toLCString(), securityConfigAsYamlString==null? FileHelper.readYamlContent(prefix+securityConfig):FileHelper.readYamlContentFromString(securityConfigAsYamlString)));

        ret.add(new IndexRequest(securityIndexName)
                .type(type)
                .id(CType.ACTIONGROUPS.toLCString())
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(CType.ACTIONGROUPS.toLCString(), FileHelper.readYamlContent(prefix+securityActionGroups)));

        ret.add(new IndexRequest(securityIndexName)
                .type(type)
                .id(CType.INTERNALUSERS.toLCString())
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(CType.INTERNALUSERS.toLCString(), FileHelper.readYamlContent(prefix+securityInternalUsers)));

        ret.add(new IndexRequest(securityIndexName)
                .type(type)
                .id(CType.ROLES.toLCString())
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(CType.ROLES.toLCString(), FileHelper.readYamlContent(prefix+securityRoles)));

        ret.add(new IndexRequest(securityIndexName)
                .type(type)
                .id(CType.ROLESMAPPING.toLCString())
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(CType.ROLESMAPPING.toLCString(), FileHelper.readYamlContent(prefix+securityRolesMapping)));
        if("".equals(legacyConfigFolder)) {
            ret.add(new IndexRequest(securityIndexName)
                    .type(type)
                    .id(CType.TENANTS.toLCString())
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(CType.TENANTS.toLCString(), FileHelper.readYamlContent(prefix+securityTenants)));
        }

        if (null != FileHelper.getAbsoluteFilePathFromClassPath(prefix + securityNodesDn)) {
            ret.add(new IndexRequest(securityIndexName)
                    .type(type)
                    .id(CType.NODESDN.toLCString())
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(CType.NODESDN.toLCString(), FileHelper.readYamlContent(prefix + securityNodesDn)));

        }

        final String whitelistYmlFile = prefix + securityWhitelist;
        if (null != FileHelper.getAbsoluteFilePathFromClassPath(whitelistYmlFile)) {
            ret.add(new IndexRequest(securityIndexName)
                    .type(type)
                    .id(CType.WHITELIST.toLCString())
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(CType.WHITELIST.toLCString(), FileHelper.readYamlContent(whitelistYmlFile)));
        }

        final String auditYmlFile = prefix + securityAudit;
        if (null != FileHelper.getAbsoluteFilePathFromClassPath(auditYmlFile)) {
            ret.add(new IndexRequest(securityIndexName)
                    .type(type)
                    .id(CType.AUDIT.toLCString())
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(CType.AUDIT.toLCString(), FileHelper.readYamlContent(auditYmlFile)));
        }

        return Collections.unmodifiableList(ret);
    }

}
