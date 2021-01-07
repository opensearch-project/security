package com.amazon.opendistroforelasticsearch.security.securityconf;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ActionGroupsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.TenantV7;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import java.util.HashSet;


public class StaticSgConfig {
    private static final Logger log = LogManager.getLogger(StaticSgConfig.class);

    private final SecurityDynamicConfiguration<RoleV7> staticRoles;
    private final SecurityDynamicConfiguration<ActionGroupsV7> staticActionGroups;
    private final SecurityDynamicConfiguration<TenantV7> staticTenants;

    public StaticSgConfig(Settings settings) {
        if (settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES, true)) {
            staticRoles = readConfig("/static_config/static_roles.yml", RoleV7.class);
            staticActionGroups = readConfig("/static_config/static_action_groups.yml", ActionGroupsV7.class);
            staticTenants = readConfig("/static_config/static_tenants.yml", TenantV7.class);
        } else {
            log.info("searchguard.unsupported.load_static_resources is set to false. Static resources will not be loaded.");
            staticRoles = SecurityDynamicConfiguration.empty();
            staticActionGroups = SecurityDynamicConfiguration.empty();
            staticTenants = SecurityDynamicConfiguration.empty();
        }
    }

    public SecurityDynamicConfiguration<?> addTo(SecurityDynamicConfiguration<?> original) {
        SecurityDynamicConfiguration<?> staticConfig = get(original);

        if (staticConfig.getCEntries().isEmpty()) {
            return original;
        }

        checkForOverriddenEntries(original, staticConfig);

        original.add(staticConfig.deepClone());

        if (log.isDebugEnabled()) {
            log.debug(staticConfig.getCEntries().size() + " static " + original.getCType().toLCString() + " loaded");
        }

        return original;
    }

    @SuppressWarnings("unchecked")
    public <ConfigType> SecurityDynamicConfiguration<ConfigType> get(SecurityDynamicConfiguration<ConfigType> original) {
        if (original.getVersion() != 2) {
            return SecurityDynamicConfiguration.empty();
        }

        switch (original.getCType()) {
            case ACTIONGROUPS:
                return (SecurityDynamicConfiguration<ConfigType>) staticActionGroups;
            case ROLES:
                return (SecurityDynamicConfiguration<ConfigType>) staticRoles;
            case TENANTS:
                return (SecurityDynamicConfiguration<ConfigType>) staticTenants;
            default:
                return SecurityDynamicConfiguration.empty();
        }

    }

    private void checkForOverriddenEntries(SecurityDynamicConfiguration<?> original, SecurityDynamicConfiguration<?> staticConfig) {
        HashSet<String> overridenKeys = new HashSet<>(staticConfig.getCEntries().keySet());
        overridenKeys.retainAll(original.getCEntries().keySet());

        if (!overridenKeys.isEmpty()) {
            log.warn("The " + original.getCType().toLCString() + " config tries to override static configuration. This is not possible. Affected config keys: " + overridenKeys);
        }
    }

    private <ConfigType> SecurityDynamicConfiguration<ConfigType> readConfig(String resourcePath, Class<ConfigType> configType) {
        try {
            JsonNode jsonNode = DefaultObjectMapper.YAML_MAPPER.readTree(DynamicConfigFactory.class.getResourceAsStream(resourcePath));

            return SecurityDynamicConfiguration.fromNode(jsonNode, CType.getByClass(configType), 2, 0, 0);
        } catch (Exception e) {
            throw new RuntimeException("Error while reading static configuration from " + resourcePath, e);
        }
    }


}
