/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework;

import java.util.List;
import java.util.Map;

public class LdapAuthorizationConfigBuilder extends LdapAuthenticationConfigBuilder<LdapAuthorizationConfigBuilder> {
    private List<String> skipUsers;
    private String roleBase;
    private String roleSearch;
    private String userRoleAttribute;
    private String userRoleName;
    private String roleName;
    private boolean resolveNestedRoles;

    public LdapAuthorizationConfigBuilder() {
        super(LdapAuthorizationConfigBuilder.class::cast);
    }

    public LdapAuthorizationConfigBuilder skipUsers(List<String> skipUsers) {
        this.skipUsers = skipUsers;
        return this;
    }

    public LdapAuthorizationConfigBuilder roleBase(String roleBase) {
        this.roleBase = roleBase;
        return this;
    }

    public LdapAuthorizationConfigBuilder roleSearch(String roleSearch) {
        this.roleSearch = roleSearch;
        return this;
    }

    public LdapAuthorizationConfigBuilder userRoleAttribute(String userRoleAttribute) {
        this.userRoleAttribute = userRoleAttribute;
        return this;
    }

    public LdapAuthorizationConfigBuilder userRoleName(String userRoleName) {
        this.userRoleName = userRoleName;
        return this;
    }

    public LdapAuthorizationConfigBuilder roleName(String roleName) {
        this.roleName = roleName;
        return this;
    }

    public LdapAuthorizationConfigBuilder resolveNestedRoles(boolean resolveNestedRoles) {
        this.resolveNestedRoles = resolveNestedRoles;
        return this;
    }

    @Override
    public Map<String, Object> build() {
        Map<String, Object> map = super.build();
        map.put("skip_users", skipUsers);
        map.put("rolebase", roleBase);
        map.put("rolesearch", roleSearch);
        map.put("userroleattribute", userRoleAttribute);
        map.put("userrolename", userRoleName);
        map.put("rolename", roleName);
        map.put("resolve_nested_roles", resolveNestedRoles);
        return map;
    }
}
