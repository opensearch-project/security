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

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import com.amazon.dlic.auth.ldap.util.Utils;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;

public class LdapUser extends User {

    private static final long serialVersionUID = 1L;
    private final transient LdapEntry userEntry;
    private final String originalUsername;

    public LdapUser(
        final String name,
        String originalUsername,
        final LdapEntry userEntry,
        final AuthCredentials credentials,
        int customAttrMaxValueLen,
        WildcardMatcher allowlistedCustomLdapAttrMatcher
    ) {
        super(name, null, credentials);
        this.originalUsername = originalUsername;
        this.userEntry = userEntry;
        Map<String, String> attributes = getCustomAttributesMap();
        attributes.putAll(extractLdapAttributes(originalUsername, userEntry, customAttrMaxValueLen, allowlistedCustomLdapAttrMatcher));
    }

    public LdapUser(StreamInput in) throws IOException {
        super(in);
        userEntry = null;
        originalUsername = in.readString();
    }

    /**
     * May return null because ldapEntry is transient
     *
     * @return ldapEntry or null if object was deserialized
     */
    public LdapEntry getUserEntry() {
        return userEntry;
    }

    public String getDn() {
        return userEntry.getDn();
    }

    public String getOriginalUsername() {
        return originalUsername;
    }

    public static Map<String, String> extractLdapAttributes(
        String originalUsername,
        final LdapEntry userEntry,
        int customAttrMaxValueLen,
        WildcardMatcher allowlistedCustomLdapAttrMatcher
    ) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("ldap.original.username", originalUsername);
        attributes.put("ldap.dn", userEntry.getDn());

        if (customAttrMaxValueLen > 0) {
            for (LdapAttribute attr : userEntry.getAttributes()) {
                if (attr != null && !attr.isBinary() && !attr.getName().toLowerCase().contains("password")) {
                    final String val = Utils.getSingleStringValue(attr);
                    // only consider attributes which are not binary and where its value is not
                    // longer than customAttrMaxValueLen characters
                    if (val != null && val.length() > 0 && val.length() <= customAttrMaxValueLen) {
                        if (allowlistedCustomLdapAttrMatcher.test(attr.getName())) {
                            attributes.put("attr.ldap." + attr.getName(), val);
                        }
                    }
                }
            }
        }
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(originalUsername);
    }
}
