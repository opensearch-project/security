/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.user;

import java.io.IOException;
import java.io.Serializable;
import java.util.*;

import com.amazon.dlic.auth.http.jwt.authtoken.api.UserAttributes;
import com.jayway.jsonpath.JsonPath;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;

import com.google.common.collect.Lists;

/**
 * A authenticated user and attributes associated to them (like roles, tenant, custom attributes)
 * <p/>
 * <b>Do not subclass from this class!</b>
 *
 */
public class User implements Serializable, Writeable, CustomAttributesAware {

    public static final User ANONYMOUS = new User("opendistro_security_anonymous", Lists.newArrayList("opendistro_security_anonymous_backendrole"), null);
    
    private static final long serialVersionUID = -5500938501822658596L;
    private final String name;
    private final String type;
    /**
     * roles == backend_roles
     */
    private final Set<String> roles = new HashSet<String>();
    private final Set<String> openDistroSecurityRoles = new HashSet<String>();
    private String requestedTenant;
    private Map<String, String> attributes = new HashMap<>();
    private Map<String, Object> structuredAttributes;
    private boolean isInjected = false;

    private final Object specialAuthzConfig;
    private boolean authzComplete;

    public User(final StreamInput in) throws IOException {
        super();
        name = in.readString();
        type = in.readOptionalString();
        roles.addAll(in.readList(StreamInput::readString));
        requestedTenant = in.readString();
        attributes = in.readMap(StreamInput::readString, StreamInput::readString);
        openDistroSecurityRoles.addAll(in.readList(StreamInput::readString));
        specialAuthzConfig = null;
    }
    
    /**
     * Create a new authenticated user
     * 
     * @param name The username (must not be null or empty)
     * @param roles Roles of which the user is a member off (maybe null)
     * @param customAttributes Custom attributes associated with this (maybe null)
     * @throws IllegalArgumentException if name is null or empty
     */
    public User(final String name, final Collection<String> roles, final AuthCredentials customAttributes) {
        super();
        this.name = name;
        this.type = null;
        this.specialAuthzConfig = null;
        configureUser(name, roles, customAttributes);
    }

    public User(final String name, String type, final Collection<String> roles, final Set<String> openDistroSecurityRoles, final AuthCredentials customAttributes, Object specialAuthzConfig) {
        super();
        this.name = name;
        this.type = type;
        this.openDistroSecurityRoles.addAll(openDistroSecurityRoles);
        this.specialAuthzConfig = specialAuthzConfig;
        configureUser(name, roles, customAttributes);
    }

    private void configureUser(final String name, final Collection<String> roles, final AuthCredentials customAttributes) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name must not be null or empty");
        }

        if (roles != null) {
            this.addRoles(roles);
        }

        this.structuredAttributes = new HashMap<>();

        if(customAttributes != null) {
            this.attributes.putAll(customAttributes.getAttributes());
            this.structuredAttributes.putAll(customAttributes.getStructuredAttributes());
        }
    }


    /**
     * Create a new authenticated user without roles and attributes
     * 
     * @param name The username (must not be null or empty)
     * @throws IllegalArgumentException if name is null or empty
     */
    public User(final String name) {
        this(name, null, null);
    }

    public final String getName() {
        return name;
    }

    /**
     * 
     * @return A unmodifiable set of the backend roles this user is a member of
     */
    public final Set<String> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    /**
     * Associate this user with a backend role
     * 
     * @param role The backend role
     */
    public final void addRole(final String role) {
        this.roles.add(role);
    }

    /**
     * Associate this user with a set of backend roles
     * 
     * @param roles The backend roles
     */
    public final void addRoles(final Collection<String> roles) {
        if(roles != null) {
            this.roles.addAll(roles);
        }
    }

    /**
     * Check if this user is a member of a backend role
     * 
     * @param role The backend role
     * @return true if this user is a member of the backend role, false otherwise
     */
    public final boolean isUserInRole(final String role) {
        return this.roles.contains(role);
    }

    /**
     * Associate this user with a set of backend roles
     * 
     * @param roles The backend roles
     */
    public final void addAttributes(final Map<String,String> attributes) {
        if(attributes != null) {
            this.attributes.putAll(attributes);
        }
    }
    
    public final String getRequestedTenant() {
        return requestedTenant;
    }

    public final void setRequestedTenant(String requestedTenant) {
        this.requestedTenant = requestedTenant;
    }
    
    
    public boolean isInjected() {
        return isInjected;
    }

    public void setInjected(boolean isInjected) {
        this.isInjected = isInjected;
    }

    public final String toStringWithAttributes() {
        return "User [name=" + name + ", backend_roles=" + roles + ", requestedTenant=" + requestedTenant + ", attributes=" + attributes + "]";
    }

    @Override
    public final String toString() {
        return "User [name=" + name + ", backend_roles=" + roles + ", requestedTenant=" + requestedTenant + "]";
    }

    @Override
    public final int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (name == null ? 0 : name.hashCode());
        return result;
    }

    @Override
    public final boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final User other = (User) obj;
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        return true;
    }

    /**
     * Copy all backend roles from another user
     * 
     * @param user The user from which the backend roles should be copied over
     */
    public final void copyRolesFrom(final User user) {
        if(user != null) {
            this.addRoles(user.getRoles());
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeStringCollection(new ArrayList<String>(roles));
        out.writeString(requestedTenant);
        out.writeMap(attributes, StreamOutput::writeString, StreamOutput::writeString);
        out.writeStringCollection(openDistroSecurityRoles==null?Collections.emptyList():new ArrayList<String>(openDistroSecurityRoles));
    }

    /**
     * Get the custom attributes associated with this user
     * 
     * @return A modifiable map with all the current custom attributes associated with this user
     */
    public synchronized final Map<String, String> getCustomAttributesMap() {
        if(attributes == null) {
            attributes = new HashMap<>();
        }
        return attributes;
    }
    
    public final void addOpenDistroSecurityRoles(final Collection<String> securityRoles) {
        if(securityRoles != null && this.openDistroSecurityRoles != null) {
            this.openDistroSecurityRoles.addAll(securityRoles);
        }
    }
    
    public final Set<String> getOpenDistroSecurityRoles() {
        return this.openDistroSecurityRoles == null ? Collections.emptySet() : Collections.unmodifiableSet(this.openDistroSecurityRoles);
    }

    public String getType() {
        return type;
    }

    public Object getSpecialAuthzConfig() {
        return specialAuthzConfig;
    }

    public Map<String, Object> getStructuredAttributes() {
        return structuredAttributes;
    }


    public Builder copy() {
        Builder builder = new Builder();
        builder.name = name;
        builder.type = type;
        builder.backendRoles.addAll(roles);
        builder.openDistroSecurityRoles.addAll(openDistroSecurityRoles);
        builder.requestedTenant = requestedTenant;
        builder.attributes.putAll(attributes);
        builder.structuredAttributes.putAll(structuredAttributes);
        builder.isInjected = isInjected;
        builder.specialAuthzConfig = specialAuthzConfig;
        builder.authzComplete = authzComplete;

        return builder;
    }


    public static class Builder {
        private String name;
        private String type;
        private final Set<String> backendRoles = new HashSet<String>();
        private final Set<String> openDistroSecurityRoles = new HashSet<String>();
        private String requestedTenant;
        private Map<String, String> attributes = new HashMap<>();
        private Map<String, Object> structuredAttributes = new HashMap<>();
        private boolean isInjected;
        private Object specialAuthzConfig;
        private boolean authzComplete;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder type(String type) {
            this.type = type;
            return this;
        }

        public Builder requestedTenant(String requestedTenant) {
            this.requestedTenant = requestedTenant;
            return this;
        }

        public Builder backendRoles(String... backendRoles) {
            return this.backendRoles(Arrays.asList(backendRoles));
        }

        public Builder backendRoles(Collection<String> backendRoles) {
            if (backendRoles != null) {
                this.backendRoles.addAll(backendRoles);
            }
            return this;
        }

        public Builder openDistroSecurityRoles(String... searchGuardRoles) {
            return this.openDistroSecurityRoles(Arrays.asList(searchGuardRoles));
        }

        public Builder openDistroSecurityRoles(Collection<String> searchGuardRoles) {
            if (searchGuardRoles != null) {
                this.openDistroSecurityRoles.addAll(searchGuardRoles);
            }
            return this;
        }

        @Deprecated
        public Builder oldAttributes(Map<String, String> attributes) {
            this.attributes.putAll(attributes);
            return this;
        }

        @Deprecated
        public Builder oldAttribute(String key, String value) {
            this.attributes.put(key, value);
            return this;
        }

        public Builder injected() {
            this.isInjected = true;
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            UserAttributes.validate(attributes);
            this.structuredAttributes.putAll(attributes);
            return this;
        }

        public Builder specialAuthzConfig(Object specialAuthzConfig) {
            this.specialAuthzConfig = specialAuthzConfig;
            return this;
        }

        public Builder authzComplete() {
            this.authzComplete = true;
            return this;
        }

        public User build() {
            return new User(name, type, openDistroSecurityRoles, backendRoles, null, specialAuthzConfig);
        }
    }

    public static Builder forUser(String username) {
        return new Builder().name(username);
    }

}
