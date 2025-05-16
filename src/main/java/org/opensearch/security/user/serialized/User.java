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
package org.opensearch.security.user.serialized;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

/**
 * This class is used for making sure that the serialized format of this User object is identical to the
 * serialized format of the User object from previous OpenSearch versions.
 * <p>
 * It is a weird property of the Java serialization mechanism that it is possible to change the resolved class in
 * ObjectInput stream, but only as long as the class name (without package name) stays the same. So, unfortunately,
 * this class needs to be named "User".
 */
public class User implements Serializable {
    private static final long serialVersionUID = -5500938501822658596L;
    private String name;
    private Set<String> roles = Collections.synchronizedSet(new HashSet<String>());
    private Set<String> securityRoles = Collections.synchronizedSet(new HashSet<String>());
    private String requestedTenant;
    private Map<String, String> attributes = Collections.synchronizedMap(new HashMap<>());
    private boolean isInjected = false;

    /**
     * Converts this objects back to User, just after deserialization
     */
    protected Object readResolve() {
        return new org.opensearch.security.user.User(
            this.name,
            resolve(this.roles),
            resolve(this.securityRoles),
            this.requestedTenant,
            resolve(this.attributes),
            this.isInjected
        );
    }

    private static ImmutableSet<String> resolve(Set<String> set) {
        if (set == null || set.isEmpty()) {
            return ImmutableSet.of();
        } else {
            return ImmutableSet.copyOf(set);
        }
    }

    private static ImmutableMap<String, String> resolve(Map<String, String> map) {
        if (map == null || map.isEmpty()) {
            return ImmutableMap.of();
        } else {
            return ImmutableMap.copyOf(map);
        }
    }
}
