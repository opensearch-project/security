/*
 * Copyright 2015-2017 floragunn GmbH
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

package com.amazon.opendistroforelasticsearch.security.ssl.transport;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;

public class DefaultPrincipalExtractor implements PrincipalExtractor {

    protected final Logger log = LogManager.getLogger(this.getClass());
    
    @Override
    public String extractPrincipal(final X509Certificate x509Certificate, final Type type) {
        if (x509Certificate == null) {
            return null;
        }

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        String dnString = AccessController.doPrivileged(new PrivilegedAction<String>() {
            @Override
            public String run() {          
                final X500Principal principal = x509Certificate.getSubjectX500Principal();
                return principal.toString();
            }
        });

        //remove whitespaces
        try {
            final LdapName ln = new LdapName(dnString);
            final List<Rdn> rdns = new ArrayList<>(ln.getRdns());
            Collections.reverse(rdns);
            dnString = String.join(",", rdns.stream().map(r->r.toString()).collect(Collectors.toList()));
        } catch (InvalidNameException e) {
            log.error("Unable to parse: {}",dnString, e);
        }
        
        
        if(log.isTraceEnabled()) {
            log.trace("principal: {}", dnString);
        }
        
        return dnString;
    }

}
