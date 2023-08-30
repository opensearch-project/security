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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.test.framework.TestSecurityConfig.Role;

import static java.util.Objects.requireNonNull;

/**
* The class represents mapping between backend roles {@link #backendRoles} to OpenSearch role defined by field {@link #roleName}. The
* class provides convenient builder-like methods and can be serialized to JSON. Serialization to JSON is required to store the class
* in an OpenSearch index which contains Security plugin configuration.
*/
public class RolesMapping implements ToXContentObject {

    /**
    * OpenSearch role name
    */
    private String roleName;

    /**
    * Backend role names
    */
    private List<String> backendRoles;
    private List<String> hostIPs;

    private boolean reserved = false;

    /**
    * Creates roles mapping to OpenSearch role defined by parameter <code>role</code>
    * @param role OpenSearch role, must not be <code>null</code>.
    */
    public RolesMapping(Role role) {
        requireNonNull(role);
        this.roleName = requireNonNull(role.getName());
        this.backendRoles = new ArrayList<>();
        this.hostIPs = new ArrayList<>();
    }

    /**
    * Defines backend role names
    * @param backendRoles backend roles names
    * @return current {@link RolesMapping} instance
    */
    public RolesMapping backendRoles(String... backendRoles) {
        this.backendRoles.addAll(Arrays.asList(backendRoles));
        return this;
    }

    /**
     * Defines host IP address
     * @param hostIPs host IP address
     * @return current {@link RolesMapping} instance
     */
    public RolesMapping hostIPs(String... hostIPs) {
        this.hostIPs.addAll(Arrays.asList(hostIPs));
        return this;
    }

    /**
    * Determines if role is reserved
    * @param reserved <code>true</code> for reserved roles
    * @return current {@link RolesMapping} instance
    */
    public RolesMapping reserved(boolean reserved) {
        this.reserved = reserved;
        return this;
    }

    /**
    * Returns OpenSearch role name
    * @return role name
    */
    public String getRoleName() {
        return roleName;
    }

    /**
    * Controls serialization to JSON
    * @param xContentBuilder must not be <code>null</code>
    * @param params not used parameter, but required by the interface {@link ToXContentObject}
    * @return builder form parameter <code>xContentBuilder</code>
    * @throws IOException denotes error during serialization to JSON
    */
    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("reserved", reserved);
        xContentBuilder.field("backend_roles", backendRoles);
        xContentBuilder.field("hosts", hostIPs);
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
