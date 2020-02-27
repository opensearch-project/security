/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.ldap;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;

import com.amazon.dlic.auth.ldap.util.Utils;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;

public class LdapUser extends User {

    private static final long serialVersionUID = 1L;
    private final transient LdapEntry userEntry;
    private final String originalUsername;

    public LdapUser(final String name, String originalUsername, final LdapEntry userEntry,
            final AuthCredentials credentials, int customAttrMaxValueLen, List<String> whiteListedAttributes) {
        super(name, null, credentials);
        this.originalUsername = originalUsername;
        this.userEntry = userEntry;
        Map<String, String> attributes = getCustomAttributesMap();
        attributes.putAll(extractLdapAttributes(originalUsername, userEntry, customAttrMaxValueLen, whiteListedAttributes));
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
    
    public static Map<String, String> extractLdapAttributes(String originalUsername, final LdapEntry userEntry
            , int customAttrMaxValueLen, List<String> whiteListedAttributes) {
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
                        if (whiteListedAttributes != null && !whiteListedAttributes.isEmpty()) {
                            if (WildcardMatcher.matchAny(whiteListedAttributes, attr.getName())) {
                                attributes.put("attr.ldap." + attr.getName(), val);
                            }
                        } else {
                            attributes.put("attr.ldap." + attr.getName(), val);
                        }
                    }
                }
            }
        }
        return Collections.unmodifiableMap(attributes);
    }
}
