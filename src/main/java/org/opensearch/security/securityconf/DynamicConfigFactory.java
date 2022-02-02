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
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.securityconf;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;

import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.securityconf.impl.NodesDn;
import org.opensearch.security.securityconf.impl.WhitelistingSettings;
import org.opensearch.security.support.WildcardMatcher;
import com.google.common.collect.ImmutableList;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.internal.InternalAuthenticationBackend;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.configuration.ConfigurationChangeListener;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.StaticResourceException;
import org.opensearch.threadpool.ThreadPool;
import org.greenrobot.eventbus.EventBus;
import org.greenrobot.eventbus.EventBusBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import org.opensearch.security.DefaultObjectMapper;
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
import org.opensearch.security.support.ConfigConstants;

import com.google.common.collect.ImmutableMap;

public class DynamicConfigFactory implements Initializable, ConfigurationChangeListener {

    public static final EventBusBuilder EVENT_BUS_BUILDER = EventBus.builder();
    private static SecurityDynamicConfiguration<RoleV7> staticRoles = SecurityDynamicConfiguration.empty();
    private static SecurityDynamicConfiguration<ActionGroupsV7> staticActionGroups = SecurityDynamicConfiguration.empty();
    private static SecurityDynamicConfiguration<TenantV7> staticTenants = SecurityDynamicConfiguration.empty();
    private static final WhitelistingSettings defaultWhitelistingSettings = new WhitelistingSettings();

    static void resetStatics() {
        staticRoles = SecurityDynamicConfiguration.empty();
        staticActionGroups = SecurityDynamicConfiguration.empty();
        staticTenants = SecurityDynamicConfiguration.empty();
    }

    private void loadStaticConfig() throws IOException {
        JsonNode staticRolesJsonNode = DefaultObjectMapper.YAML_MAPPER
                .readTree(DynamicConfigFactory.class.getResourceAsStream("/static_config/static_roles.yml"));
        staticRoles = SecurityDynamicConfiguration.fromNode(staticRolesJsonNode, CType.ROLES, 2, 0, 0);

        JsonNode staticActionGroupsJsonNode = DefaultObjectMapper.YAML_MAPPER
                .readTree(DynamicConfigFactory.class.getResourceAsStream("/static_config/static_action_groups.yml"));
        staticActionGroups = SecurityDynamicConfiguration.fromNode(staticActionGroupsJsonNode, CType.ACTIONGROUPS, 2, 0, 0);

        JsonNode staticTenantsJsonNode = DefaultObjectMapper.YAML_MAPPER
                .readTree(DynamicConfigFactory.class.getResourceAsStream("/static_config/static_tenants.yml"));
        staticTenants = SecurityDynamicConfiguration.fromNode(staticTenantsJsonNode, CType.TENANTS, 2, 0, 0);
    }

    public final static SecurityDynamicConfiguration<?> addStatics(SecurityDynamicConfiguration<?> original) {
        if(original.getCType() == CType.ACTIONGROUPS && !staticActionGroups.getCEntries().isEmpty()) {
            original.add(staticActionGroups.deepClone());
        }

        if(original.getCType() == CType.ROLES && !staticRoles.getCEntries().isEmpty()) {
            original.add(staticRoles.deepClone());
        }

        if(original.getCType() == CType.TENANTS && !staticTenants.getCEntries().isEmpty()) {
            original.add(staticTenants.deepClone());
        }

        return original;
    }
    
    protected final Logger log = LoggerFactory.getLogger(this.getClass());
    private final ConfigurationRepository cr;
    private final AtomicBoolean initialized = new AtomicBoolean();
    private final EventBus eventBus = EVENT_BUS_BUILDER.build();
    private final Settings opensearchSettings;
    private final Path configPath;
    private final InternalAuthenticationBackend iab = new InternalAuthenticationBackend();

    SecurityDynamicConfiguration<?> config;
    
    public DynamicConfigFactory(ConfigurationRepository cr, final Settings opensearchSettings,
            final Path configPath, Client client, ThreadPool threadPool, ClusterInfoHolder cih) {
        super();
        this.cr = cr;
        this.opensearchSettings = opensearchSettings;
        this.configPath = configPath;

        if(opensearchSettings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES, true)) {
            try {
                loadStaticConfig();
            } catch (IOException e) {
                throw new StaticResourceException("Unable to load static resources due to "+e, e);
            }
        } else {
            log.info("Static resources will not be loaded.");
        }
        
        if(opensearchSettings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES, true)) {
            try {
                loadStaticConfig();
            } catch (IOException e) {
                throw new StaticResourceException("Unable to load static resources due to "+e, e);
            }
        } else {
            log.info("Static resources will not be loaded.");
        }
        
        registerDCFListener(this.iab);
        this.cr.subscribeOnChange(this);
    }
    
    @Override
    public void onChange(Map<CType, SecurityDynamicConfiguration<?>> typeToConfig) {

        SecurityDynamicConfiguration<?> actionGroups = cr.getConfiguration(CType.ACTIONGROUPS);
        config = cr.getConfiguration(CType.CONFIG);
        SecurityDynamicConfiguration<?> internalusers = cr.getConfiguration(CType.INTERNALUSERS);
        SecurityDynamicConfiguration<?> roles = cr.getConfiguration(CType.ROLES);
        SecurityDynamicConfiguration<?> rolesmapping = cr.getConfiguration(CType.ROLESMAPPING);
        SecurityDynamicConfiguration<?> tenants = cr.getConfiguration(CType.TENANTS);
        SecurityDynamicConfiguration<?> nodesDn = cr.getConfiguration(CType.NODESDN);
        SecurityDynamicConfiguration<?> whitelistingSetting = cr.getConfiguration(CType.WHITELIST);


        if (log.isDebugEnabled()) {
            String logmsg = "current config (because of " + typeToConfig.keySet() + ")\n" +
                    " actionGroups: " + actionGroups.getImplementingClass() + " with " + actionGroups.getCEntries().size() + " entries\n" +
                    " config: " + config.getImplementingClass() + " with " + config.getCEntries().size() + " entries\n" +
                    " internalusers: " + internalusers.getImplementingClass() + " with " + internalusers.getCEntries().size() + " entries\n" +
                    " roles: " + roles.getImplementingClass() + " with " + roles.getCEntries().size() + " entries\n" +
                    " rolesmapping: " + rolesmapping.getImplementingClass() + " with " + rolesmapping.getCEntries().size() + " entries\n" +
                    " tenants: " + tenants.getImplementingClass() + " with " + tenants.getCEntries().size() + " entries\n" +
                    " nodesdn: " + nodesDn.getImplementingClass() + " with " + nodesDn.getCEntries().size() + " entries\n" +
                    " whitelist " + whitelistingSetting.getImplementingClass() + " with " + whitelistingSetting.getCEntries().size() + " entries\n";
            log.debug(logmsg);
            
        }

        final DynamicConfigModel dcm;
        final InternalUsersModel ium;
        final ConfigModel cm;
        final NodesDnModel nm = new NodesDnModelImpl(nodesDn);
        final WhitelistingSettings whitelist = (WhitelistingSettings) cr.getConfiguration(CType.WHITELIST).getCEntry("config");
        final AuditConfig audit = (AuditConfig)cr.getConfiguration(CType.AUDIT).getCEntry("config");

        if(config.getImplementingClass() == ConfigV7.class) {
                //statics
                
                if(roles.containsAny(staticRoles)) {
                    throw new StaticResourceException("Cannot override static roles");
                }
                if(!roles.add(staticRoles) && !staticRoles.getCEntries().isEmpty()) {
                    throw new StaticResourceException("Unable to load static roles");
                }

                log.debug("Static roles loaded ({})", staticRoles.getCEntries().size());

                if(actionGroups.containsAny(staticActionGroups)) {
                    System.out.println("static: " + actionGroups.getCEntries());
                    System.out.println("Static Action Groups:" + staticActionGroups.getCEntries());
                    throw new StaticResourceException("Cannot override static action groups");
                }
                if(!actionGroups.add(staticActionGroups) && !staticActionGroups.getCEntries().isEmpty()) {
                    throw new StaticResourceException("Unable to load static action groups");
                }
                

                log.debug("Static action groups loaded ({})", staticActionGroups.getCEntries().size());
                
                if(tenants.containsAny(staticTenants)) {
                    throw new StaticResourceException("Cannot override static tenants");
                }
                if(!tenants.add(staticTenants) && !staticTenants.getCEntries().isEmpty()) {
                    throw new StaticResourceException("Unable to load static tenants");
                }
                

                log.debug("Static tenants loaded ({})", staticTenants.getCEntries().size());

                log.debug("Static configuration loaded (total roles: {}/total action groups: {}/total tenants: {})",
                    roles.getCEntries().size(), actionGroups.getCEntries().size(), tenants.getCEntries().size());

            

            //rebuild v7 Models
            dcm = new DynamicConfigModelV7(getConfigV7(config), opensearchSettings, configPath, iab);
            ium = new InternalUsersModelV7((SecurityDynamicConfiguration<InternalUserV7>) internalusers,
                (SecurityDynamicConfiguration<RoleV7>) roles,
                (SecurityDynamicConfiguration<RoleMappingsV7>) rolesmapping);
            cm = new ConfigModelV7((SecurityDynamicConfiguration<RoleV7>) roles,(SecurityDynamicConfiguration<RoleMappingsV7>)rolesmapping, (SecurityDynamicConfiguration<ActionGroupsV7>)actionGroups, (SecurityDynamicConfiguration<TenantV7>) tenants,dcm, opensearchSettings);

        } else {

            //rebuild v6 Models
            dcm = new DynamicConfigModelV6(getConfigV6(config), opensearchSettings, configPath, iab);
            ium = new InternalUsersModelV6((SecurityDynamicConfiguration<InternalUserV6>) internalusers);
            cm = new ConfigModelV6((SecurityDynamicConfiguration<RoleV6>) roles, (SecurityDynamicConfiguration<ActionGroupsV6>)actionGroups, (SecurityDynamicConfiguration<RoleMappingsV6>)rolesmapping, dcm, opensearchSettings);

        }

        //notify subscribers
        eventBus.post(cm);
        eventBus.post(dcm);
        eventBus.post(ium);
        eventBus.post(nm);
        eventBus.post(whitelist==null? defaultWhitelistingSettings: whitelist);
        if (cr.isAuditHotReloadingEnabled()) {
            eventBus.post(audit);
        }

        initialized.set(true);
        
    }
    
    private static ConfigV6 getConfigV6(SecurityDynamicConfiguration<?> sdc) {
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<ConfigV6> c = (SecurityDynamicConfiguration<ConfigV6>) sdc;
        return c.getCEntry("opendistro_security");
    }
    
    private static ConfigV7 getConfigV7(SecurityDynamicConfiguration<?> sdc) {
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<ConfigV7> c = (SecurityDynamicConfiguration<ConfigV7>) sdc;
        return c.getCEntry("config");
    }
    
    @Override
    public final boolean isInitialized() {
        return initialized.get();
    }
    
    public void registerDCFListener(Object listener) {
        eventBus.register(listener);
    }

    public void unregisterDCFListener(Object listener) {
        eventBus.unregister(listener);
    }
    
    private static class InternalUsersModelV7 extends InternalUsersModel {
        
        private final SecurityDynamicConfiguration<InternalUserV7> internalUserV7SecurityDynamicConfiguration;

        private final SecurityDynamicConfiguration<RoleV7> rolesV7SecurityDynamicConfiguration;

        private final SecurityDynamicConfiguration<RoleMappingsV7> rolesMappingsV7SecurityDynamicConfiguration;
        
        public InternalUsersModelV7(SecurityDynamicConfiguration<InternalUserV7> internalUserV7SecurityDynamicConfiguration,
                                    SecurityDynamicConfiguration<RoleV7> rolesV7SecurityDynamicConfiguration,
                                    SecurityDynamicConfiguration<RoleMappingsV7> rolesMappingsV7SecurityDynamicConfiguration) {
            super();
            this.internalUserV7SecurityDynamicConfiguration = internalUserV7SecurityDynamicConfiguration;
            this.rolesV7SecurityDynamicConfiguration = rolesV7SecurityDynamicConfiguration;
            this.rolesMappingsV7SecurityDynamicConfiguration = rolesMappingsV7SecurityDynamicConfiguration;
        }

        @Override
        public boolean exists(String user) {
            return internalUserV7SecurityDynamicConfiguration.exists(user);
        }

        @Override
        public List<String> getBackenRoles(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);
            return tmp==null?null:tmp.getBackend_roles();
        }

        @Override
        public Map<String, String> getAttributes(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);
            return tmp==null?null:tmp.getAttributes();
        }

        @Override
        public String getDescription(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);
            return tmp==null?null:tmp.getDescription();
        }

        @Override
        public String getHash(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);
            return tmp==null?null:tmp.getHash();
        }
        
        public List<String> getSecurityRoles(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);

            // Security roles should only contain roles that exist in the roles dynamic config.
            // We should filter out any roles that have hidden rolesmapping.
            return tmp == null ? ImmutableList.of() :
                tmp.getOpendistro_security_roles().stream().filter(role -> !isRolesMappingHidden(role) && rolesV7SecurityDynamicConfiguration.exists(role)).collect(ImmutableList.toImmutableList());
        }

        // Remove any hidden rolesmapping from the security roles
        private boolean isRolesMappingHidden(String rolename) {
            final RoleMappingsV7 roleMapping = rolesMappingsV7SecurityDynamicConfiguration.getCEntry(rolename);
            return roleMapping!=null && roleMapping.isHidden();
        }
    }
    
    private static class InternalUsersModelV6 extends InternalUsersModel {
        
        SecurityDynamicConfiguration<InternalUserV6> configuration;
        

        public InternalUsersModelV6(SecurityDynamicConfiguration<InternalUserV6> configuration) {
            super();
            this.configuration = configuration;
        }

        @Override
        public boolean exists(String user) {
            return configuration.exists(user);
        }

        @Override
        public List<String> getBackenRoles(String user) {
            InternalUserV6 tmp = configuration.getCEntry(user);
            return tmp==null?null:tmp.getRoles();
        }

        @Override
        public Map<String, String> getAttributes(String user) {
            InternalUserV6 tmp = configuration.getCEntry(user);
            return tmp==null?null:tmp.getAttributes();
        }

        @Override
        public String getDescription(String user) {
            return null;
        }

        @Override
        public String getHash(String user) {
            InternalUserV6 tmp = configuration.getCEntry(user);
            return tmp==null?null:tmp.getHash();
        }
        
        public List<String> getSecurityRoles(String user) {
            return Collections.emptyList();
        }
    }

    private static class NodesDnModelImpl extends NodesDnModel {

        SecurityDynamicConfiguration<NodesDn> configuration;

        public NodesDnModelImpl(SecurityDynamicConfiguration<?> configuration) {
            super();
            this.configuration = null == configuration.getCType() ? SecurityDynamicConfiguration.empty() :
                (SecurityDynamicConfiguration<NodesDn>)configuration;
        }

        @Override
        public Map<String, WildcardMatcher> getNodesDn() {
            return this.configuration.getCEntries().entrySet().stream().collect(
                    ImmutableMap.toImmutableMap(Entry::getKey, entry -> WildcardMatcher.from(entry.getValue().getNodesDn(), false)));
        }
    }
}
