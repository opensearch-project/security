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

package com.amazon.dlic.auth.ldap.util;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.ldaptive.Connection;
import org.ldaptive.DerefAliases;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResult;
import org.ldaptive.SearchScope;
import org.ldaptive.referral.SearchReferralHandler;

import org.opensearch.SpecialPermission;

public class LdapHelper {

    private static SearchFilter ALL = new SearchFilter("(objectClass=*)");
    @SuppressWarnings("removal")
    public static List<LdapEntry> search(final Connection conn, final String unescapedDn, SearchFilter filter,
            final SearchScope searchScope, final String[] returnAttributes, boolean shouldFollowReferrals) throws LdapException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        try {
            final String baseDn = escapeDn(unescapedDn);
            return AccessController.doPrivileged(new PrivilegedExceptionAction<List<LdapEntry>>() {
                @Override
                public List<LdapEntry> run() throws Exception {
                    final List<LdapEntry> entries = new ArrayList<>();
                    final SearchRequest request = new SearchRequest(baseDn, filter);

                    request.setSearchScope(searchScope);
                    request.setDerefAliases(DerefAliases.ALWAYS);
                    request.setReturnAttributes(returnAttributes);
                    final SearchOperation search = new SearchOperation(conn);

                    if (shouldFollowReferrals) {
                         // referrals will be followed to build the response
                        request.setReferralHandler(new SearchReferralHandler());
                    }

                    final Response<SearchResult> r = search.execute(request);
                    final org.ldaptive.SearchResult result = r.getResult();
                    entries.addAll(result.getEntries());

                    return entries;
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getException() instanceof LdapException) {
                throw (LdapException) e.getException();
            } else if (e.getException() instanceof RuntimeException) {
                throw (RuntimeException) e.getException();
            } else {
                throw new RuntimeException(e);
            }
        }catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }
    }

    public static LdapEntry lookup(final Connection conn, final String unescapedDn, final String[] returnAttributes, boolean shouldFollowReferrals) throws LdapException {

        final List<LdapEntry> entries = search(conn, unescapedDn, ALL, SearchScope.OBJECT, returnAttributes, shouldFollowReferrals);

        if (entries.size() == 1) {
            return entries.get(0);
        } else {
            return null;
        }
    }

    private static String escapeDn(String dn) throws InvalidNameException {
        final LdapName dnName = new LdapName(dn);
        final List<Rdn> escaped = new ArrayList<>(dnName.size());
        for(Rdn rdn: dnName.getRdns()) {
            escaped.add(new Rdn(rdn.getType(), escapeForwardSlash(rdn.getValue())));
        }
        return new LdapName(escaped).toString();
    }

    private static Object escapeForwardSlash(Object input) {
        if(input != null && input instanceof String) {
            return ((String)input).replace("/", "\\2f");
        } else {
            return input;
        }

    }

}
