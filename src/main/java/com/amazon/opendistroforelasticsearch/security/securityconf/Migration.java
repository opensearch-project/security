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
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.Meta;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.NodesDn;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.WhitelistingSettings;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.*;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.*;
import org.opensearch.common.Strings;
import org.opensearch.common.collect.Tuple;



public class Migration {
    
    public static Tuple<SecurityDynamicConfiguration<RoleV7>,SecurityDynamicConfiguration<TenantV7>>  migrateRoles(SecurityDynamicConfiguration<RoleV6> r6cs, SecurityDynamicConfiguration<RoleMappingsV6> rms6) throws MigrationException {
        
        final SecurityDynamicConfiguration<RoleV7> r7 = SecurityDynamicConfiguration.empty();
        r7.setCType(r6cs.getCType());
        r7.set_meta(new Meta());
        r7.get_meta().setConfig_version(2);
        r7.get_meta().setType("roles");
        
        final SecurityDynamicConfiguration<TenantV7> t7 = SecurityDynamicConfiguration.empty();
        t7.setCType(CType.TENANTS);
        t7.set_meta(new Meta());
        t7.get_meta().setConfig_version(2);
        t7.get_meta().setType("tenants");

        Set<String> dedupTenants = new HashSet<>();
        
        for(final Entry<String, RoleV6> r6e: r6cs.getCEntries().entrySet()) {
            final String roleName  = r6e.getKey();
            final RoleV6 r6 = r6e.getValue();
            
            if(r6 == null) {
                RoleV7 noPermRole = new RoleV7();
                noPermRole.setDescription("Migrated from v6, was empty");
                r7.putCEntry(roleName, noPermRole);
                continue;
            }

            r7.putCEntry(roleName, new RoleV7(r6));
            
            for(Entry<String, String> tenant: r6.getTenants().entrySet()) {
                dedupTenants.add(tenant.getKey());
            }
        }
        
        if(rms6 != null) {
            for(final Entry<String, RoleMappingsV6> r6m: rms6.getCEntries().entrySet()) {
                final String roleName  = r6m.getKey();
                //final RoleMappingsV6 r6 = r6m.getValue();
                
                if(!r7.exists(roleName)) {
                    //rolemapping but role does not exists
                    RoleV7 noPermRole = new RoleV7();
                    noPermRole.setDescription("Migrated from v6, was in rolemappings but no role existed");
                    r7.putCEntry(roleName, noPermRole);
                }
                
            }
        }
        
        for(String tenantName: dedupTenants) {
            TenantV7 entry = new TenantV7();
            entry.setDescription("Migrated from v6");
            t7.putCEntry(tenantName, entry);
        }
        
        return new Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>>(r7, t7);
        
    }
    
    public static SecurityDynamicConfiguration<ConfigV7> migrateConfig(SecurityDynamicConfiguration<ConfigV6> r6cs) throws MigrationException {
        final SecurityDynamicConfiguration<ConfigV7> c7 = SecurityDynamicConfiguration.empty();
        c7.setCType(r6cs.getCType());
        c7.set_meta(new Meta());
        c7.get_meta().setConfig_version(2);
        c7.get_meta().setType("config");
        
        if(r6cs.getCEntries().size() != 1) {
            throw new MigrationException("Unable to migrate config because expected size was 1 but actual size is "+r6cs.getCEntries().size());
        }
        
        if(r6cs.getCEntries().get("opendistro_security") == null) {
            throw new MigrationException("Unable to migrate config because 'opendistro_security' key not found");
        }
        
        for(final Entry<String, ConfigV6> r6c: r6cs.getCEntries().entrySet()) {
            c7.putCEntry("config", new ConfigV7(r6c.getValue()));
        }
        return c7;
    }

    public static SecurityDynamicConfiguration<NodesDn> migrateNodesDn(SecurityDynamicConfiguration<NodesDn> nodesDn) {
        final SecurityDynamicConfiguration<NodesDn> migrated = SecurityDynamicConfiguration.empty();
        migrated.setCType(nodesDn.getCType());
        migrated.set_meta(new Meta());
        migrated.get_meta().setConfig_version(2);
        migrated.get_meta().setType("nodesdn");

        for(final Entry<String, NodesDn> entry: nodesDn.getCEntries().entrySet()) {
            migrated.putCEntry(entry.getKey(), new NodesDn(entry.getValue()));
        }
        return migrated;
    }

    public static SecurityDynamicConfiguration<WhitelistingSettings> migrateWhitelistingSetting(SecurityDynamicConfiguration<WhitelistingSettings> whitelistingSetting) {
        final SecurityDynamicConfiguration<WhitelistingSettings> migrated = SecurityDynamicConfiguration.empty();
        migrated.setCType(whitelistingSetting.getCType());
        migrated.set_meta(new Meta());
        migrated.get_meta().setConfig_version(2);
        migrated.get_meta().setType("whitelist");

        for(final Entry<String, WhitelistingSettings> entry: whitelistingSetting.getCEntries().entrySet()) {
            migrated.putCEntry(entry.getKey(), new WhitelistingSettings(entry.getValue()));
        }
        return migrated;
    }

    public static SecurityDynamicConfiguration<InternalUserV7>  migrateInternalUsers(SecurityDynamicConfiguration<InternalUserV6> r6is) throws MigrationException {
        final SecurityDynamicConfiguration<InternalUserV7> i7 = SecurityDynamicConfiguration.empty();
        i7.setCType(r6is.getCType());
        i7.set_meta(new Meta());
        i7.get_meta().setConfig_version(2);
        i7.get_meta().setType("internalusers");
        
        for(final Entry<String, InternalUserV6> r6i: r6is.getCEntries().entrySet()) {
            final  String username = !Strings.isNullOrEmpty(r6i.getValue().getUsername())?r6i.getValue().getUsername():r6i.getKey();
            i7.putCEntry(username, new InternalUserV7(r6i.getValue()));
        }
        
        return i7;
    }
    
    public static SecurityDynamicConfiguration<ActionGroupsV7>  migrateActionGroups(SecurityDynamicConfiguration<?> r6as) throws MigrationException {
        
        final SecurityDynamicConfiguration<ActionGroupsV7> a7 = SecurityDynamicConfiguration.empty();
        a7.setCType(r6as.getCType());
        a7.set_meta(new Meta());
        a7.get_meta().setConfig_version(2);
        a7.get_meta().setType("actiongroups");
        
        if(r6as.getImplementingClass().isAssignableFrom(List.class)) {
            for(final Entry<String, ?> r6a: r6as.getCEntries().entrySet()) {
                a7.putCEntry(r6a.getKey(), new ActionGroupsV7(r6a.getKey(), (List<String>) r6a.getValue()));
            }
        } else {
            for(final Entry<String, ?> r6a: r6as.getCEntries().entrySet()) {
                a7.putCEntry(r6a.getKey(), new ActionGroupsV7(r6a.getKey(), (ActionGroupsV6)r6a.getValue()));
            }
        }

        return a7;
    }
    
    public static SecurityDynamicConfiguration<RoleMappingsV7>  migrateRoleMappings(SecurityDynamicConfiguration<RoleMappingsV6> r6rms) throws MigrationException {
        final SecurityDynamicConfiguration<RoleMappingsV7> rms7 = SecurityDynamicConfiguration.empty();
        rms7.setCType(r6rms.getCType());
        rms7.set_meta(new Meta());
        rms7.get_meta().setConfig_version(2);
        rms7.get_meta().setType("rolesmapping");
        
        for(final Entry<String, RoleMappingsV6> r6m: r6rms.getCEntries().entrySet()) {
            rms7.putCEntry(r6m.getKey(), new RoleMappingsV7(r6m.getValue()));
        }
        
        return rms7;
    }

    public static SecurityDynamicConfiguration<AuditConfig> migrateAudit(SecurityDynamicConfiguration<AuditConfig> audit) {
        final SecurityDynamicConfiguration<AuditConfig> migrated = SecurityDynamicConfiguration.empty();
        migrated.setCType(audit.getCType());
        migrated.set_meta(new Meta());
        migrated.get_meta().setConfig_version(2);
        migrated.get_meta().setType("audit");

        for(final Entry<String, AuditConfig> entry: audit.getCEntries().entrySet()) {
            migrated.putCEntry(entry.getKey(), entry.getValue());
        }
        return migrated;
    }

}
