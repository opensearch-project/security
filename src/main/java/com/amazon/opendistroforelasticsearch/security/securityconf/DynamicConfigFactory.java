package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auth.internal.InternalAuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationChangeListener;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.configuration.StaticResourceException;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ActionGroupsV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.InternalUserV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.RoleMappingsV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.RoleV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ActionGroupsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.InternalUserV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleMappingsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.TenantV7;

public class DynamicConfigFactory implements Initializable, ConfigurationChangeListener {
    
    private static final SecurityDynamicConfiguration<RoleV7> staticRoles;
    private static final SecurityDynamicConfiguration<ActionGroupsV7> staticActionGroups;
    private static final SecurityDynamicConfiguration<TenantV7> staticTenants;
    
    static {
        try {
            JsonNode staticRolesJsonNode = DefaultObjectMapper.YAML_MAPPER.readTree(DynamicConfigFactory.class.getResourceAsStream("/static_config/static_roles.yml"));
            staticRoles = SecurityDynamicConfiguration.fromNode(staticRolesJsonNode, CType.ROLES, 2, 0, 0);
            JsonNode staticActionGroupsJsonNode = DefaultObjectMapper.YAML_MAPPER.readTree(DynamicConfigFactory.class.getResourceAsStream("/static_config/static_action_groups.yml"));
            staticActionGroups = SecurityDynamicConfiguration.fromNode(staticActionGroupsJsonNode, CType.ACTIONGROUPS, 2, 0, 0);
            JsonNode staticTenantsJsonNode = DefaultObjectMapper.YAML_MAPPER.readTree(DynamicConfigFactory.class.getResourceAsStream("/static_config/static_tenants.yml"));
            staticTenants = SecurityDynamicConfiguration.fromNode(staticTenantsJsonNode, CType.TENANTS, 2, 0, 0);
        } catch (Exception e) {
            throw ExceptionsHelper.convertToRuntime(e);
        }
    }
    
    public static final SecurityDynamicConfiguration<RoleV7> getStaticRoles() {
        return staticRoles.deepClone();
    }
    
    public static final SecurityDynamicConfiguration<ActionGroupsV7> getStaticActionGroups() {
        return staticActionGroups.deepClone();
    }
    
    public static final SecurityDynamicConfiguration<TenantV7> getStaticTenants() {
        return staticTenants.deepClone();
    }
    
    public static final SecurityDynamicConfiguration<?> addStatics(SecurityDynamicConfiguration<?> original) {
        if(original.getCType() == CType.ACTIONGROUPS) {
            original.add(getStaticActionGroups());
        }
        
        if(original.getCType() == CType.ROLES) {
            original.add(getStaticRoles());
        }
        
        if(original.getCType() == CType.TENANTS) {
            original.add(getStaticTenants());
        }
        
        return original;
    }
    
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final ConfigurationRepository cr;
    private final AtomicBoolean initialized = new AtomicBoolean();
    private final List<DCFListener> listeners = new ArrayList<>();
    private final Settings esSettings;
    private final Path configPath;
    private final InternalAuthenticationBackend iab = new InternalAuthenticationBackend();

    SecurityDynamicConfiguration<?> config;
    
    public DynamicConfigFactory(ConfigurationRepository cr, final Settings esSettings, 
            final Path configPath, Client client, ThreadPool threadPool, ClusterInfoHolder cih) {
        super();
        this.cr = cr;
        this.esSettings = esSettings;
        this.configPath = configPath;
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
        
        if(log.isDebugEnabled()) {
            String logmsg = "current config (because of "+typeToConfig.keySet()+")\n"+
            " actionGroups: "+actionGroups.getImplementingClass()+" with "+actionGroups.getCEntries().size()+" entries\n"+
            " config: "+config.getImplementingClass()+" with "+config.getCEntries().size()+" entries\n"+
            " internalusers: "+internalusers.getImplementingClass()+" with "+internalusers.getCEntries().size()+" entries\n"+
            " roles: "+roles.getImplementingClass()+" with "+roles.getCEntries().size()+" entries\n"+
            " rolesmapping: "+rolesmapping.getImplementingClass()+" with "+rolesmapping.getCEntries().size()+" entries\n"+
            " tenants: "+tenants.getImplementingClass()+" with "+tenants.getCEntries().size()+" entries";
            log.debug(logmsg);
            
        }

        if(config.getImplementingClass() == ConfigV7.class) {
                //statics
                
                if(roles.containsAny(staticRoles)) {
                    throw new StaticResourceException("Cannot override static roles");
                }
                if(!roles.add(staticRoles)) {
                    throw new StaticResourceException("Unable to load static roles");
                }

                log.debug("Static roles loaded ({})", staticRoles.getCEntries().size());

                if(actionGroups.containsAny(staticActionGroups)) {
                    System.out.println("static: " + actionGroups.getCEntries());
                    System.out.println("Static Action Groups:" + staticActionGroups.getCEntries());
                    throw new StaticResourceException("Cannot override static action groups");
                }
                if(!actionGroups.add(staticActionGroups)) {
                    throw new StaticResourceException("Unable to load static action groups");
                }
                

                log.debug("Static action groups loaded ({})", staticActionGroups.getCEntries().size());
                
                if(tenants.containsAny(staticTenants)) {
                    throw new StaticResourceException("Cannot override static tenants");
                }
                if(!tenants.add(staticTenants)) {
                    throw new StaticResourceException("Unable to load static tenants");
                }
                

                log.debug("Static tenants loaded ({})", staticTenants.getCEntries().size());

                log.debug("Static configuration loaded (total roles: {}/total action groups: {}/total tenants: {})", roles.getCEntries().size(), actionGroups.getCEntries().size(), tenants.getCEntries().size());

            

            //rebuild v7 Models
            DynamicConfigModel dcm = new DynamicConfigModelV7(getConfigV7(config), esSettings, configPath, iab);
            InternalUsersModel ium = new InternalUsersModelV7((SecurityDynamicConfiguration<InternalUserV7>) internalusers);
            ConfigModel cm = new ConfigModelV7((SecurityDynamicConfiguration<RoleV7>) roles,(SecurityDynamicConfiguration<RoleMappingsV7>)rolesmapping, (SecurityDynamicConfiguration<ActionGroupsV7>)actionGroups, (SecurityDynamicConfiguration<TenantV7>) tenants,dcm, esSettings);

            //notify listeners
            
            for(DCFListener listener: listeners) {
                listener.onChanged(cm, dcm, ium);
            }
        
        } else {

            //rebuild v6 Models
            DynamicConfigModel dcmv6 = new DynamicConfigModelV6(getConfigV6(config), esSettings, configPath, iab);
            InternalUsersModel iumv6 = new InternalUsersModelV6((SecurityDynamicConfiguration<InternalUserV6>) internalusers);
            ConfigModel cmv6 = new ConfigModelV6((SecurityDynamicConfiguration<RoleV6>) roles, (SecurityDynamicConfiguration<ActionGroupsV6>)actionGroups, (SecurityDynamicConfiguration<RoleMappingsV6>)rolesmapping, dcmv6, esSettings);
            
            //notify listeners
            
            for(DCFListener listener: listeners) {
                listener.onChanged(cmv6, dcmv6, iumv6);
            }
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
    
    public void registerDCFListener(DCFListener listener) {
        listeners.add(listener);
    }
    
    public static interface DCFListener {
        void onChanged(ConfigModel cm, DynamicConfigModel dcm, InternalUsersModel ium);
    }
    
    private static class InternalUsersModelV7 extends InternalUsersModel {
        
        SecurityDynamicConfiguration<InternalUserV7> configuration;
        
        public InternalUsersModelV7(SecurityDynamicConfiguration<InternalUserV7> configuration) {
            super();
            this.configuration = configuration;
        }

        @Override
        public boolean exists(String user) {
            return configuration.exists(user);
        }

        @Override
        public List<String> getBackenRoles(String user) {
            InternalUserV7 tmp = configuration.getCEntry(user);
            return tmp==null?null:tmp.getBackend_roles();
        }

        @Override
        public Map<String, String> getAttributes(String user) {
            InternalUserV7 tmp = configuration.getCEntry(user);
            return tmp==null?null:tmp.getAttributes();
        }

        @Override
        public String getDescription(String user) {
            InternalUserV7 tmp = configuration.getCEntry(user);
            return tmp==null?null:tmp.getDescription();
        }

        @Override
        public String getHash(String user) {
            InternalUserV7 tmp = configuration.getCEntry(user);
            return tmp==null?null:tmp.getHash();
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
        
    }
   
}
