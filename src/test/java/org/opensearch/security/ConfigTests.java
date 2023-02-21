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

package org.opensearch.security;

import java.io.File;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.Strings;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.securityconf.Migration;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v6.ActionGroupsV6;
import org.opensearch.security.securityconf.impl.v6.ConfigV6;
import org.opensearch.security.securityconf.impl.v6.InternalUserV6;
import org.opensearch.security.securityconf.impl.v6.RoleMappingsV6;
import org.opensearch.security.securityconf.impl.v6.RoleV6;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.securityconf.impl.v7.TenantV7;
import org.opensearch.security.test.SingleClusterTest;

public class ConfigTests {
    
    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());
    
    @Test
    public void testEmptyConfig() throws Exception {
        Assert.assertTrue(SecurityDynamicConfiguration.empty().deepClone() != SecurityDynamicConfiguration.empty());
    }
    
    @Test
    public void testMigrate() throws Exception {

        Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>> rolesResult = Migration.migrateRoles((SecurityDynamicConfiguration<RoleV6>)load("./legacy/securityconfig_v6/roles.yml", CType.ROLES),
                (SecurityDynamicConfiguration<RoleMappingsV6>)load("./legacy/securityconfig_v6/roles_mapping.yml", CType.ROLESMAPPING));
        
        System.out.println(Strings.toString(XContentType.JSON, rolesResult.v2(), true, false));
        System.out.println(Strings.toString(XContentType.JSON, rolesResult.v1(), true, false));
        
        
        SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsResult = Migration.migrateActionGroups((SecurityDynamicConfiguration<ActionGroupsV6>)load("./legacy/securityconfig_v6/action_groups.yml", CType.ACTIONGROUPS));
        System.out.println(Strings.toString(XContentType.JSON, actionGroupsResult, true, false));
        SecurityDynamicConfiguration<ConfigV7> configResult =Migration.migrateConfig((SecurityDynamicConfiguration<ConfigV6>)load("./legacy/securityconfig_v6/config.yml", CType.CONFIG));
        System.out.println(Strings.toString(XContentType.JSON, configResult, true, false));
        SecurityDynamicConfiguration<InternalUserV7> internalUsersResult = Migration.migrateInternalUsers((SecurityDynamicConfiguration<InternalUserV6>)load("./legacy/securityconfig_v6/internal_users.yml", CType.INTERNALUSERS));
        System.out.println(Strings.toString(XContentType.JSON, internalUsersResult, true, false));
        SecurityDynamicConfiguration<RoleMappingsV7> rolemappingsResult = Migration.migrateRoleMappings((SecurityDynamicConfiguration<RoleMappingsV6>)load("./legacy/securityconfig_v6/roles_mapping.yml", CType.ROLESMAPPING));
        System.out.println(Strings.toString(XContentType.JSON, rolemappingsResult, true, false));
    }
    
    @Test
    public void testParseSg67Config() throws Exception {

        check("./legacy/securityconfig_v6/action_groups.yml", CType.ACTIONGROUPS);
        check("./action_groups.yml", CType.ACTIONGROUPS);
        
        check("./legacy/securityconfig_v6/config.yml", CType.CONFIG);
        check("./config.yml", CType.CONFIG);
        
        check("./legacy/securityconfig_v6/roles.yml", CType.ROLES);
        check("./roles.yml", CType.ROLES);
        
        check("./legacy/securityconfig_v6/internal_users.yml", CType.INTERNALUSERS);
        check("./internal_users.yml", CType.INTERNALUSERS);
        
        check("./legacy/securityconfig_v6/roles_mapping.yml", CType.ROLESMAPPING);
        check("./roles_mapping.yml", CType.ROLESMAPPING);
        
        check("./tenants.yml", CType.TENANTS);
        
    }
    
    private void check(String file, CType cType) throws Exception {
        final String adjustedFilePath = SingleClusterTest.TEST_RESOURCE_RELATIVE_PATH + file;
        JsonNode jsonNode = YAML.readTree(FileUtils.readFileToString(new File(adjustedFilePath), "UTF-8"));
        int configVersion = 1;
        System.out.println("%%%%%%%% THIS IS A LINE OF INTEREST %%%%%%%");
        if(jsonNode.get("_meta") != null) {
            Assert.assertEquals(jsonNode.get("_meta").get("type").asText(), cType.toLCString());
            configVersion = jsonNode.get("_meta").get("config_version").asInt();
        }


        System.out.println("%%%%%%%% THIS IS A LINE OF INTEREST: CONFIG VERSION: "+ configVersion + "%%%%%%%");
        
        SecurityDynamicConfiguration<?> dc = load(file, cType);
        Assert.assertNotNull(dc);
        //Assert.assertTrue(dc.getCEntries().size() > 0);
        String jsonSerialize = DefaultObjectMapper.objectMapper.writeValueAsString(dc);
        SecurityDynamicConfiguration<?> conf = SecurityDynamicConfiguration.fromJson(jsonSerialize, cType, configVersion, 0, 0);
        SecurityDynamicConfiguration.fromJson(Strings.toString(XContentType.JSON, conf), cType, configVersion, 0, 0);
        
    }
    
    private SecurityDynamicConfiguration<?> load(String file, CType cType) throws Exception {
        final String adjustedFilePath = SingleClusterTest.TEST_RESOURCE_RELATIVE_PATH + file;
        JsonNode jsonNode = YAML.readTree(FileUtils.readFileToString(new File(adjustedFilePath), "UTF-8"));
        int configVersion = 1;

        System.out.println("%%%%%%%% THIS IS A LINE OF INTEREST LOAD: CONFIG VERSION: %%%%%%%");
        if(jsonNode.get("_meta") != null) {
            Assert.assertEquals(jsonNode.get("_meta").get("type").asText(), cType.toLCString());
            configVersion = jsonNode.get("_meta").get("config_version").asInt();
        }
        System.out.println("%%%%%%%% THIS IS A LINE OF INTEREST: CONFIG VERSION: "+ configVersion + "%%%%%%%");
        return SecurityDynamicConfiguration.fromNode(jsonNode, cType, configVersion, 0, 0);
    }
}
