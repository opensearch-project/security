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

package org.opensearch.security.securityconf;

import org.opensearch.security.support.WildcardMatcher;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class TypePerm {
    protected final WildcardMatcher typeMatcher;
    private final Set<String> perms = new HashSet<>();

    TypePerm(String typePattern) {
        this.typeMatcher = WildcardMatcher.ANY;
    }

    protected TypePerm addPerms(Collection<String> perms) {
        if (perms != null) {
            this.perms.addAll(perms);
        }
        return this;
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
        return System.lineSeparator() + "             typePattern=" + typeMatcher + System.lineSeparator() + "             perms=" + perms;
    }

    public WildcardMatcher getTypeMatcher() {
        return typeMatcher;
    }

    public WildcardMatcher getPerms() {
        return WildcardMatcher.from(perms);
    }

}
