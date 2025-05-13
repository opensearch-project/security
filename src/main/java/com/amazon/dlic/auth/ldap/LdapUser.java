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

package com.amazon.dlic.auth.ldap;

/**
 * This class intentionally remains in the com.amazon.dlic.auth.ldap package
 * to maintain compatibility with serialization/deserialization in mixed cluster
 * environments (nodes running different versions). The class is serialized and
 * passed between nodes, and changing the package would break backward compatibility.
 *
 * This class is only used for deserialization. During deserialization, the readResolve()
 * method will automatically convert it to a org.opensearch.security.user.User user object.
 * It will never be used for serialization, only the org.opensearch.security.user.User user object
 * will be serialized. This is possible because the additional attributes of LdapUser were only
 * needed during the auth/auth phase, where no inter-node communication is necessary. Afterwards,
 * the user object is never used as LdapUser, but just as a plain User object.
 *
 * This class can be removed as soon as it is no longer possible that a mixed cluster can contain
 * nodes which send serialized LdapUser objects. This will be the case for OpenSearch 4.0.
 *
 * @see https://github.com/opensearch-project/security/pull/5223
 */
public class LdapUser extends org.opensearch.security.user.serialized.User {

    private static final long serialVersionUID = 1L;
    private final String originalUsername;

    public LdapUser() {
        this.originalUsername = null;
    }

    /**
     * Converts this objects back to User, just after deserialization.
     * <p>
     * Note: We do not convert back to LdapUser, but just to User. The additional attributes of
     * LdapUser were only needed during the auth/auth phase, where no inter-node communication
     * is necessary. Afterwards, the user object is never used as LdapUser, but just as a plain User
     * object.
     */
    protected Object readResolve() {
        return super.readResolve();
    }
}
