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

package org.opensearch.security.securityconf;

import org.opensearch.security.support.WildcardMatcher;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class TypePerm {
    protected final WildcardMatcher typeMatcher;
    private final Set<String> perms = new HashSet<>();

    TypePerm() {
        this.typeMatcher = WildcardMatcher.ANY;
    }

    public WildcardMatcher getTypeMatcher() {
        return typeMatcher;
    }

    public WildcardMatcher getPermsMatcher() {
        return WildcardMatcher.from(perms);
    }

    protected void addPerms(Collection<String> perms) {
        if (perms != null) {
            this.perms.addAll(perms);
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((perms == null) ? 0 : perms.hashCode());
        result = prime * result + ((typeMatcher == null) ? 0 : typeMatcher.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        TypePerm other = (TypePerm) obj;
        if (perms == null) {
            if (other.perms != null) return false;
        } else if (!perms.equals(other.perms)) return false;
        if (typeMatcher == null) {
            if (other.typeMatcher != null) return false;
        } else if (!typeMatcher.equals(other.typeMatcher)) return false;
        return true;
    }

    @Override
    public String toString() {
        return "TypePerm{" + "typeMatcher=" + typeMatcher + ", perms=" + perms + '}';
    }
}
