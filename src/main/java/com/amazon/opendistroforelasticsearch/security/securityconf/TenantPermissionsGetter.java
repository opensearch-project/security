package com.amazon.opendistroforelasticsearch.security.securityconf;

import com.google.common.collect.ImmutableSet;

import java.util.Collections;
import java.util.Set;

public class TenantPermissionsGetter {
    protected static final String KIBANA_ALL_SAVED_OBJECTS_WRITE = "kibana:saved_objects/*/write";
    protected static final Set<String> KIBANA_ALL_SAVED_OBJECTS_WRITE_SET = ImmutableSet.of(KIBANA_ALL_SAVED_OBJECTS_WRITE);

    public static class TenantPermissionsImpl implements SecurityRoles.TenantPermissions {


        private final Set<String> permissions;

        public TenantPermissionsImpl(Set<String> permissions) {
            this.permissions = Collections.unmodifiableSet(permissions);
        }

        public boolean isReadPermitted() {
            return permissions.size() > 0;
        }

        public boolean isWritePermitted() {
            return permissions.contains(KIBANA_ALL_SAVED_OBJECTS_WRITE) || permissions.contains("*");
        }

        public Set<String> getPermissions() {
            return permissions;
        }
    }

    protected final static Set<String> SET_OF_EVERYTHING = ImmutableSet.of("*");


    protected static final SecurityRoles.TenantPermissions RW_TENANT_PERMISSIONS = new SecurityRoles.TenantPermissions() {


        @Override
        public boolean isWritePermitted() {
            return true;
        }

        @Override
        public boolean isReadPermitted() {
            return true;
        }

        @Override
        public Set<String> getPermissions() {
            return KIBANA_ALL_SAVED_OBJECTS_WRITE_SET;
        }
    };

    protected static final SecurityRoles.TenantPermissions FULL_TENANT_PERMISSIONS = new SecurityRoles.TenantPermissions() {


        @Override
        public boolean isWritePermitted() {
            return true;
        }

        @Override
        public boolean isReadPermitted() {
            return true;
        }

        @Override
        public Set<String> getPermissions() {
            return SET_OF_EVERYTHING;
        }
    };

    protected static final SecurityRoles.TenantPermissions EMPTY_TENANT_PERMISSIONS = new SecurityRoles.TenantPermissions() {
        @Override
        public boolean isWritePermitted() {
            return false;
        }

        @Override
        public boolean isReadPermitted() {
            return false;
        }

        @Override
        public Set<String> getPermissions() {
            return Collections.emptySet();
        }
    };
}
