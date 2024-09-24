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

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JavaType;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.NonValidatingObjectMapper;
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

/**
 * Identifies configuration types. A `CType` instance has a 1-to-1 relationship with a configuration
 * business object class, which is referenced in its generic parameter.
 * <p>
 * Additionally, a `CType` can reference older versions of these business objects via the `oldConfigVersions`
 * property.
 * <p>
 * In earlier versions, `CType` was an `enum` which leads to a few peculiarities:
 * <ul>
 *     <li>Each instance needs to have a unique `id` which corresponds to the `ord` property
 *     from Java enums. OpenSearch uses these ids for its own transport message serialization.
 *     These ids must not be changed, otherwise backward compatibility will be broken.
 *     <li>Each instance has several names. One, that is used for identifying the document
 *     in document ids. Another one that is used for identifying the config type by yaml file names. There
 *     are a few inconsistencies - for the future, it is recommendable to use identical names.
 * </ul>
 */
public class CType<T> implements Comparable<CType<?>> {

    private final static Set<CType<?>> allSet = new HashSet<>();
    private static Map<String, CType<?>> nameToInstanceMap = new HashMap<>();
    private static Map<Integer, CType<?>> ordToInstanceMap = new HashMap<>();

    public static final CType<ActionGroupsV7> ACTIONGROUPS = new CType<>(
        "actiongroups",
        "action_groups",
        ActionGroupsV7.class,
        0,
        false,
        new OldConfigVersion<>(1, ActionGroupsV6.class, ActionGroupsV7::new)
    );
    public static final CType<AllowlistingSettings> ALLOWLIST = new CType<>("allowlist", "allowlist", AllowlistingSettings.class, 1, true);
    public static final CType<AuditConfig> AUDIT = new CType<>("audit", "audit", AuditConfig.class, 2, true);
    public static final CType<ConfigV7> CONFIG = new CType<>(
        "config",
        "config",
        ConfigV7.class,
        3,
        false,
        new OldConfigVersion<>(1, ConfigV6.class, ConfigV7::new, ConfigV6::convertMapKeyToV7)
    );
    public static final CType<InternalUserV7> INTERNALUSERS = new CType<>(
        "internalusers",
        "internal_users",
        InternalUserV7.class,
        4,
        false,
        new OldConfigVersion<>(1, InternalUserV6.class, InternalUserV7::new)
    );
    public static final CType<NodesDn> NODESDN = new CType<>("nodesdn", "nodes_dn", NodesDn.class, 5, true);
    public static final CType<RoleV7> ROLES = new CType<>(
        "roles",
        "roles",
        RoleV7.class,
        6,
        false,
        new OldConfigVersion<>(1, RoleV6.class, RoleV7::new)
    );
    public static final CType<RoleMappingsV7> ROLESMAPPING = new CType<>(
        "rolesmapping",
        "roles_mapping",
        RoleMappingsV7.class,
        7,
        false,
        new OldConfigVersion<>(1, RoleMappingsV6.class, RoleMappingsV7::new)
    );
    public static final CType<TenantV7> TENANTS = new CType<>("tenants", "tenants", TenantV7.class, 8, false);
    public static final CType<WhitelistingSettings> WHITELIST = new CType<>("whitelist", "whitelist", WhitelistingSettings.class, 9, true);

    private final String name;
    private final String nameUpperCase;
    private final Class<T> configClass;
    private final String configFileName;
    private final boolean emptyIfMissing;
    private final OldConfigVersion<?, T>[] oldConfigVersions;
    private final int id;

    @SafeVarargs
    @SuppressWarnings("varargs")
    private CType(
        String name,
        String configFileName,
        Class<T> configClass,
        int id,
        boolean emptyIfMissing,
        OldConfigVersion<?, T>... oldConfigVersions
    ) {
        this.name = name;
        this.nameUpperCase = name.toUpperCase();
        this.configClass = configClass;
        this.id = id;
        this.configFileName = configFileName + ".yml";
        this.emptyIfMissing = emptyIfMissing;
        this.oldConfigVersions = oldConfigVersions;

        allSet.add(this);
        nameToInstanceMap.put(name, this);
        ordToInstanceMap.put(id, this);
    }

    public Class<T> getConfigClass() {
        return this.configClass;
    }

    public boolean emptyIfMissing() {
        return emptyIfMissing;
    }

    public String toLCString() {
        return this.name;
    }

    public String name() {
        return this.name;
    }

    public int getOrd() {
        return id;
    }

    public static CType<?> fromString(String value) {
        return nameToInstanceMap.get(value.toLowerCase());
    }

    public static Set<CType<?>> values() {
        return Collections.unmodifiableSet(allSet);
    }

    public static Set<String> lcStringValues() {
        return CType.values().stream().map(CType::toLCString).collect(Collectors.toSet());
    }

    public static Set<CType<?>> fromStringValues(String[] strings) {
        return Arrays.stream(strings).map(CType::fromString).collect(Collectors.toSet());
    }

    public static CType<?> fromOrd(int ord) {
        return ordToInstanceMap.get(ord);
    }

    public static Set<CType<?>> requiredConfigTypes() {
        return values().stream().filter(Predicate.not(CType::emptyIfMissing)).collect(Collectors.toUnmodifiableSet());
    }

    public static Set<CType<?>> notRequiredConfigTypes() {
        return values().stream().filter(CType::emptyIfMissing).collect(Collectors.toUnmodifiableSet());
    }

    public Path configFile(final Path configDir) {
        return configDir.resolve(this.configFileName);
    }

    public String configFileName() {
        return configFileName;
    }

    public OldConfigVersion<?, T> findOldConfigVersion(int versionNumber) {
        for (OldConfigVersion<?, T> oldConfigVersion : this.oldConfigVersions) {
            if (versionNumber == oldConfigVersion.versionNumber) {
                return oldConfigVersion;
            }
        }

        return null;
    }

    @Override
    public int compareTo(CType<?> cType) {
        return this.id - cType.id;
    }

    @Override
    public String toString() {
        return this.nameUpperCase;
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof CType) {
            return ((CType<?>) other).id == this.id;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return id;
    }

    public static class OldConfigVersion<OldType, NewType> {
        private final int versionNumber;
        private final Class<OldType> oldType;
        private final Function<OldType, NewType> entryConversionFunction;
        private final Function<String, String> mapKeyConversionFunction;

        public OldConfigVersion(int versionNumber, Class<OldType> oldType, Function<OldType, NewType> entryConversionFunction) {
            this.versionNumber = versionNumber;
            this.oldType = oldType;
            this.entryConversionFunction = entryConversionFunction;
            this.mapKeyConversionFunction = Function.identity();
        }

        public OldConfigVersion(
            int versionNumber,
            Class<OldType> oldType,
            Function<OldType, NewType> entryConversionFunction,
            Function<String, String> mapKeyConversionFunction
        ) {
            this.versionNumber = versionNumber;
            this.oldType = oldType;
            this.entryConversionFunction = entryConversionFunction;
            this.mapKeyConversionFunction = mapKeyConversionFunction;
        }

        public int getVersionNumber() {
            return versionNumber;
        }

        public Class<OldType> getOldType() {
            return oldType;
        }

        public Function<OldType, NewType> getEntryConversionFunction() {
            return entryConversionFunction;
        }

        public SecurityDynamicConfiguration<NewType> parseJson(CType<NewType> ctype, String json, boolean acceptInvalid)
            throws IOException {
            JavaType javaType = DefaultObjectMapper.getTypeFactory().constructParametricType(SecurityDynamicConfiguration.class, oldType);

            if (acceptInvalid) {
                return convert(NonValidatingObjectMapper.readValue(json, javaType), ctype);
            } else {
                return convert(DefaultObjectMapper.readValue(json, javaType), ctype);
            }
        }

        public SecurityDynamicConfiguration<NewType> convert(SecurityDynamicConfiguration<OldType> oldConfig, CType<NewType> ctype) {
            SecurityDynamicConfiguration<NewType> newConfig = SecurityDynamicConfiguration.empty(ctype);
            newConfig.setAutoConvertedFrom(oldConfig);
//            newConfig.setSeqNoPrimaryTerm();

            for (Map.Entry<String, OldType> oldEntry : oldConfig.getCEntries().entrySet()) {
                newConfig.putCEntry(mapKeyConversionFunction.apply(oldEntry.getKey()), entryConversionFunction.apply(oldEntry.getValue()));
            }

            return newConfig;
        }

    }
}
