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

package org.opensearch.security.http;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.AuthCredentials;

public class HTTPClientCertAuthenticator implements HTTPAuthenticator {
    
    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Settings settings;

    public HTTPClientCertAuthenticator(final Settings settings, final Path configPath) {
        this.settings = settings;
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request, final ThreadContext threadContext) {

        final String principal = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);

        if (!Strings.isNullOrEmpty(principal)) {
            
            final String usernameAttribute = settings.get("username_attribute");
            final String rolesAttribute = settings.get("roles_attribute");
            
            try {
                final LdapName rfc2253dn = new LdapName(principal);
                String username = principal.trim();
                String[] backendRoles = null;
                
                if(usernameAttribute != null && usernameAttribute.length() > 0) {
                    final List<String> usernames = getDnAttribute(rfc2253dn, usernameAttribute);
                    if(usernames.isEmpty() == false) {
                        username = usernames.get(0);
                    }
                }
                
                if(rolesAttribute != null && rolesAttribute.length() > 0) {
                    final List<String> roles = getDnAttribute(rfc2253dn, rolesAttribute);
                    if(roles.isEmpty() == false) {
                        backendRoles = roles.toArray(new String[0]);
                    }
                }
                
                return new AuthCredentials(username, backendRoles).markComplete();
            } catch (InvalidNameException e) {
                log.error("Client cert had no properly formed DN (was: {})", principal);
                return null;
            }

        } else {
            log.trace("No CLIENT CERT, send 401");
            return null;
        }
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        return false;
    }

    @Override
    public String getType() {
        return "clientcert";
    }
    
    private List<String> getDnAttribute(LdapName rfc2253dn, String attribute) {        
        final List<String> attrValues = new ArrayList<>(rfc2253dn.size());
        final List<Rdn> reverseRdn = new ArrayList<>(rfc2253dn.getRdns());
        Collections.reverse(reverseRdn);

        for (Rdn rdn : reverseRdn) {
            if (rdn.getType().equalsIgnoreCase(attribute)) {
                attrValues.add(rdn.getValue().toString());
            }
        }
        
        return Collections.unmodifiableList(attrValues);
    }
}
