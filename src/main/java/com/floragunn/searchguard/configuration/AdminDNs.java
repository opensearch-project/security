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

package com.floragunn.searchguard.configuration;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Iterables;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Multimaps;

public class AdminDNs {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Set<LdapName> adminDn = new HashSet<LdapName>();
    private final ListMultimap<LdapName, String> allowedImpersonations = ArrayListMultimap.<LdapName, String> create();
    
    @Inject
    public AdminDNs(Settings settings) 
    {
        final String[] adminDnsA = settings.getAsArray("searchguard.authcz.admin_dn");

        for (int i = 0; i < adminDnsA.length; i++) {
            final String dn = adminDnsA[i];
            try {
                log.debug(dn);
                adminDn.add(new LdapName(dn));
            } catch (final InvalidNameException e) {
                log.error("Unable to parse admin dn {} {}",e, dn, e);
            }
        }
        
        log.debug("Loaded {} admin DN's {}",adminDn.size(),  adminDn);
        
        final Map<String, Settings> impersonationDns = settings.getGroups("searchguard.authcz.impersonation_dn");

        for (String dnString:impersonationDns.keySet()) {
            try {
                allowedImpersonations.putAll(new LdapName(dnString), Arrays.asList(settings.getAsArray("searchguard.authcz.impersonation_dn."+dnString)));
            } catch (final InvalidNameException e) {
                log.error("Unable to parse allowedImpersonations dn {} {}",e, dnString, e);
            }
        }
        
        log.debug("Loaded {} impersonation DN's {}",allowedImpersonations.size(), allowedImpersonations);
    }
    
    public boolean isAdmin(String dn) {
        
        if(dn == null) return false;
        
        try {
            return isAdmin(new LdapName(dn));
        } catch (InvalidNameException e) {
           return false;
        }
    }
    
    public boolean isAdmin(LdapName dn) {
        if(dn == null) return false;
        
        return adminDn.contains(dn);
    }
    
    public boolean isImpersonationAllowed(LdapName dn, String impersonated) {
        if(dn == null) return false;
        
        if(isAdmin(dn)) {
            return true;
        }
        
        return this.allowedImpersonations.containsEntry(dn, impersonated);
    }
}
