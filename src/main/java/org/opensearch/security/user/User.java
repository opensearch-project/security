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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.user;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import org.opensearch.security.support.Base64Helper;

/**
 * A authenticated user and attributes associated to them (like roles, tenant, custom attributes)
 * <p/>
 * <b>Do not subclass from this class!</b>
 *
 */
public class User implements Serializable, CustomAttributesAware {

    public static final User ANONYMOUS = new User("opendistro_security_anonymous").withRole("opendistro_security_anonymous_backendrole");

    // This is a default user that is injected into a transport request when a user info is not present and passive_intertransport_auth is
    // enabled.
    // This is to be used in scenarios where some of the nodes do not have security enabled, and therefore do not pass any user information
    // in threadcontext, yet we need the communication to not break between the nodes.
    // Attach the required permissions to either the user or the backend role.
    public static final User DEFAULT_TRANSPORT_USER = new User("opendistro_security_default_transport_user").withRole(
        "opendistro_security_default_transport_backendrole"
    );

    /**
     * Deserializes the given serialized from of a user object and returns the actual user object.
     *
     * Note: Instead of using this method, prefer to use UserFactory.Caching to benefit from already parsed user objects.
     */
    public static User fromSerializedBase64(String serializedBase64) {
        User user = (User) Base64Helper.deserializeObject(serializedBase64);
        user.serializedBase64 = serializedBase64;
        return user;
    }

    private static final long serialVersionUID = -5500938501822658596L;
    private final String name;

    /**
     * roles == backend_roles
     */
    private final ImmutableSet<String> roles;
    private final ImmutableSet<String> securityRoles;
    private final String requestedTenant;
    private final ImmutableMap<String, String> attributes;
    private final boolean isInjected;
    private volatile transient String serializedBase64;

    /**
     * Create a new authenticated user
     *
     * @param name The username (must not be null or empty)
     * @param roles Roles of which the user is a member off (maybe null)
     * @param customAttributes Custom attributes associated with this (maybe null)
     * @throws IllegalArgumentException if name is null or empty
     */
    public User(final String name, final Collection<String> roles, final AuthCredentials customAttributes) {
        this(
            name,
            ImmutableSet.copyOf(roles),
            ImmutableSet.of(),
            null,
            customAttributes != null ? ImmutableMap.copyOf(customAttributes.getAttributes()) : ImmutableMap.of(),
            false
        );
    }

    /**
     * Create a new authenticated user without roles and attributes
     *
     * @param name The username (must not be null or empty)
     * @throws IllegalArgumentException if name is null or empty
     */
    public User(final String name) {
        this(name, ImmutableSet.of(), null);
    }

    public User(
        String name,
        ImmutableSet<String> roles,
        ImmutableSet<String> securityRoles,
        String requestedTenant,
        ImmutableMap<String, String> attributes,
        boolean isInjected
    ) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name must not be null or empty");
        }

        this.name = name;
        this.roles = Objects.requireNonNull(roles);
        this.securityRoles = Objects.requireNonNull(securityRoles);
        this.requestedTenant = requestedTenant;
        this.attributes = Objects.requireNonNull(attributes);
        this.isInjected = isInjected;
    }

    public final String getName() {
        return name;
    }

    /**
     *
     * @return A unmodifiable set of the backend roles this user is a member of
     */
    public ImmutableSet<String> getRoles() {
        return this.roles;
    }

    /**
     * Associate this user with a backend role
     *
     * @param role The backend role
     */
    public User withRole(String role) {
        return new User(
            this.name,
            new ImmutableSet.Builder<String>().addAll(this.roles).add(role).build(),
            this.securityRoles,
            this.requestedTenant,
            this.attributes,
            this.isInjected
        );
    }

    /**
     * Associate this user with a set of backend roles
     *
     * @param roles The backend roles
     */
    public User withRoles(Collection<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return this;
        } else {
            return new User(
                this.name,
                new ImmutableSet.Builder<String>().addAll(this.roles).addAll(roles).build(),
                this.securityRoles,
                this.requestedTenant,
                this.attributes,
                this.isInjected
            );
        }
    }

    /**
     * Associate this user with a set of custom attributes
     *
     * @param attributes custom attributes
     */
    public User withAttributes(Map<String, String> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            return this;
        } else {
            return new User(
                this.name,
                this.roles,
                this.securityRoles,
                this.requestedTenant,
                new ImmutableMap.Builder<String, String>().putAll(this.attributes).putAll(attributes).build(),
                this.isInjected
            );
        }
    }

    public final String getRequestedTenant() {
        return requestedTenant;
    }

    public User withRequestedTenant(String requestedTenant) {
        if (Objects.equals(requestedTenant, this.requestedTenant)) {
            return this;
        } else {
            return new User(this.name, this.roles, this.securityRoles, requestedTenant, this.attributes, this.isInjected);
        }
    }

    public boolean isInjected() {
        return isInjected;
    }

    public final String toStringWithAttributes() {
        return "User [name="
            + name
            + ", backend_roles="
            + roles
            + ", requestedTenant="
            + requestedTenant
            + ", attributes="
            + attributes
            + "]";
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
        if (!(obj instanceof User)) {
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
     * Get the custom attributes associated with this user
     *
     * @return An immutable map with all the current custom attributes associated with this user
     */
    public ImmutableMap<String, String> getCustomAttributesMap() {
        return this.attributes;
    }

    public User withSecurityRoles(Collection<String> securityRoles) {
        if (securityRoles == null || securityRoles.isEmpty()) {
            return this;
        } else {
            return new User(
                this.name,
                this.roles,
                new ImmutableSet.Builder<String>().addAll(this.securityRoles).addAll(securityRoles).build(),
                this.requestedTenant,
                this.attributes,
                this.isInjected
            );
        }
    }

    public ImmutableSet<String> getSecurityRoles() {
        return this.securityRoles;
    }

    /**
     * Check the custom attributes associated with this user
     *
     * @return true if it has a service account attributes, otherwise false
     */
    public boolean isServiceAccount() {
        Map<String, String> userAttributesMap = this.getCustomAttributesMap();
        return userAttributesMap != null && "true".equals(userAttributesMap.get("attr.internal.service"));
    }

    /**
     * Check the custom attributes associated with this user
     *
     * @return true if it has a plugin account attributes, otherwise false
     */
    public boolean isPluginUser() {
        return name != null && name.startsWith("plugin:");
    }

    public String toSerializedBase64() {
        String result = this.serializedBase64;

        if (result == null) {
            this.serializedBase64 = result = Base64Helper.serializeObject(this);
        }

        return result;
    }

    void readObject(ObjectInputStream stream) throws InvalidObjectException {
        // This object is not supposed to directly read in order to keep compatibility with older OpenSearch versions
        throw new InvalidObjectException("Use org.opensearch.security.user.serialized.User");
    }

    @Serial
    private static final ObjectStreamField[] serialPersistentFields = {
        new ObjectStreamField("name", String.class),
        new ObjectStreamField("roles", Collections.synchronizedSet(Collections.emptySet()).getClass()),
        new ObjectStreamField("securityRoles", Collections.synchronizedSet(Collections.emptySet()).getClass()),
        new ObjectStreamField("requestedTenant", String.class),
        new ObjectStreamField("attributes", Collections.synchronizedMap(Collections.emptyMap()).getClass()),
        new ObjectStreamField("isInjected", Boolean.TYPE) };

    /**
     * Creates a backwards compatible object that can be used for serialization
     */
    @Serial
    private void writeObject(ObjectOutputStream out) throws IOException {
        ObjectOutputStream.PutField fields = out.putFields();
        fields.put("name", name);
        fields.put("roles", Collections.synchronizedSet(new HashSet<>(this.roles)));
        fields.put("securityRoles", Collections.synchronizedSet(new HashSet<>(this.securityRoles)));
        fields.put("requestedTenant", requestedTenant);
        fields.put("attributes", Collections.synchronizedMap(new HashMap<>(this.attributes)));
        fields.put("isInjected", this.isInjected);

        out.writeFields();
    }
}
