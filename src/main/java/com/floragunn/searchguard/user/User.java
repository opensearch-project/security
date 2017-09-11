/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.user;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.Lists;

public class User implements Serializable {

    public static final User ANONYMOUS = new User("sg_anonymous", Lists.newArrayList("sg_anonymous_backendrole"));
    
    @Deprecated
    public static final User SG_INTERNAL = new User("_sg_internal");
    
    private static final long serialVersionUID = -5500938501822658596L;
    private final String name;
    private final Set<String> roles = new HashSet<String>();
    private String requestedTenant;

    public User(final String name, final Collection<String> toAdd) {
        super();

        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name must not be null or empty");
        }

        this.name = name;

        if (toAdd != null) {
            this.addRoles(toAdd);
        }

    }

    public User(final String name) {
        this(name, null);
    }

    public String getName() {
        return name;
    }

    public Set<String> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    public void addRole(final String role) {
        roles.add(role);
    }

    public void addRoles(final Collection<String> toAdd) {
        roles.addAll(toAdd);
    }

    public boolean isUserInRole(final String role) {
        return roles.contains(role);
    }
    
    public String getRequestedTenant() {
        return requestedTenant;
    }

    public void setRequestedTenant(String requestedTenant) {
        this.requestedTenant = requestedTenant;
    }

    @Override
    public String toString() {
        return "User [name=" + name + ", roles=" + roles + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (name == null ? 0 : name.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
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

    public void copyRolesFrom(final User user) {
        this.addRoles(user.getRoles());
    }
}
