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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.support.ConfigConstants;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;

public class AdminDNs {

    protected final Logger log = LogManager.getLogger(AdminDNs.class);
    private final Set<LdapName> adminDn = new HashSet<LdapName>();
    private final ListMultimap<LdapName, String> allowedImpersonations = ArrayListMultimap.<LdapName, String> create();
    
    public AdminDNs(Settings settings) 
    {
        final String[] adminDnsA = settings.getAsArray(ConfigConstants.SEARCHGUARD_AUTHCZ_ADMIN_DN, new String[0]);

        for (int i = 0; i < adminDnsA.length; i++) {
            final String dn = adminDnsA[i];
            try {
                log.debug("{} is registered as an admin dn", dn);
                adminDn.add(new LdapName(dn));
            } catch (final InvalidNameException e) {
                log.error("Unable to parse admin dn {} {}",e, dn, e);
            }
        }
       
        log.debug("Loaded {} admin DN's {}",adminDn.size(),  adminDn);
        
        final Map<String, Settings> impersonationDns = settings.getGroups(ConfigConstants.SEARCHGUARD_AUTHCZ_IMPERSONATION_DN);

        for (String dnString:impersonationDns.keySet()) {
            try {
                allowedImpersonations.putAll(new LdapName(dnString), Arrays.asList(settings.getAsArray(ConfigConstants.SEARCHGUARD_AUTHCZ_IMPERSONATION_DN+"."+dnString)));
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

    private boolean isAdmin(LdapName dn) {
        if(dn == null) return false;
        
        boolean isAdmin = adminDn.contains(dn);
        
        if (log.isTraceEnabled()) {
            log.trace("Is principal {} an admin cert? {}", dn.toString(), isAdmin);
        }
        
        return isAdmin;
    }
    
    public boolean isImpersonationAllowed(LdapName dn, String impersonated) {
        if(dn == null) return false;
        
        if(isAdmin(dn)) {
            return true;
        }
        
        return this.allowedImpersonations.containsEntry(dn, "*") || this.allowedImpersonations.containsEntry(dn, impersonated);
    }
}
