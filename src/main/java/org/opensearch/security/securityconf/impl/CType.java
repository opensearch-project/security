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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.securityconf.impl;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;

import org.opensearch.security.auditlog.config.AuditConfig;
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

public enum CType {

    ACTIONGROUPS(toMap(0, List.class, 1, ActionGroupsV6.class, 2, ActionGroupsV7.class), "action_groups.yml", false),
    ALLOWLIST(toMap(1, AllowlistingSettings.class, 2, AllowlistingSettings.class), "allowlist.yml", true),
    AUDIT(toMap(1, AuditConfig.class, 2, AuditConfig.class), "audit.yml", true),
    CONFIG(toMap(1, ConfigV6.class, 2, ConfigV7.class), "config.yml", false),
    INTERNALUSERS(toMap(1, InternalUserV6.class, 2, InternalUserV7.class), "internal_users.yml", false),
    NODESDN(toMap(1, NodesDn.class, 2, NodesDn.class), "nodes_dn.yml", true),
    ROLES(toMap(1, RoleV6.class, 2, RoleV7.class), "roles.yml", false),
    ROLESMAPPING(toMap(1, RoleMappingsV6.class, 2, RoleMappingsV7.class), "roles_mapping.yml", false),
    TENANTS(toMap(2, TenantV7.class), "tenants.yml", false),
    WHITELIST(toMap(1, WhitelistingSettings.class, 2, WhitelistingSettings.class), "whitelist.yml", true);

    public static final List<CType> REQUIRED_CONFIG_FILES = Arrays.stream(CType.values())
        .filter(Predicate.not(CType::emptyIfMissing))
        .collect(Collectors.toList());

    public static final List<CType> NOT_REQUIRED_CONFIG_FILES = Arrays.stream(CType.values())
        .filter(CType::emptyIfMissing)
        .collect(Collectors.toList());

    private final Map<Integer, Class<?>> implementations;

    private final String configFileName;

    private final boolean emptyIfMissing;

    private CType(Map<Integer, Class<?>> implementations, final String configFileName, final boolean emptyIfMissing) {
        this.implementations = implementations;
        this.configFileName = configFileName;
        this.emptyIfMissing = emptyIfMissing;
    }

    public boolean emptyIfMissing() {
        return emptyIfMissing;
    }

    public Map<Integer, Class<?>> getImplementationClass() {
        return Collections.unmodifiableMap(implementations);
    }

    public static CType fromString(String value) {
        return CType.valueOf(value.toUpperCase());
    }

    public String toLCString() {
        return this.toString().toLowerCase();
    }

    public static Set<String> lcStringValues() {
        return Arrays.stream(CType.values()).map(CType::toLCString).collect(Collectors.toSet());
    }

    public static Set<CType> fromStringValues(String[] strings) {
        return Arrays.stream(strings).map(CType::fromString).collect(Collectors.toSet());
    }

    public Path configFile(final Path configDir) {
        return configDir.resolve(this.configFileName);
    }

    public String configFileName() {
        return configFileName;
    }

    private static Map<Integer, Class<?>> toMap(Object... objects) {
        final ImmutableMap.Builder<Integer, Class<?>> map = ImmutableMap.builder();
        for (int i = 0; i < objects.length; i = i + 2) {
            map.put((Integer) objects[i], (Class<?>) objects[i + 1]);
        }
        return map.build();
    }
}
