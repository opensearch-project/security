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

package org.opensearch.security.auth.ldap.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import com.google.common.annotations.VisibleForTesting;

import org.opensearch.secure_sm.AccessController;

import org.ldaptive.Connection;
import org.ldaptive.DerefAliases;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.ResultCode;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResult;
import org.ldaptive.SearchScope;
import org.ldaptive.referral.SearchReferralHandler;

public class LdapHelper {

    private static SearchFilter ALL = new SearchFilter("(objectClass=*)");

    public static List<LdapEntry> search(
        final Connection conn,
        final String unescapedDn,
        SearchFilter filter,
        final SearchScope searchScope,
        final String[] returnAttributes,
        boolean shouldFollowReferrals
    ) throws LdapException {

        try {
            final String baseDn = escapeDn(unescapedDn);
            return AccessController.doPrivilegedChecked(() -> {
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
            });
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Reads the entry with the given DN.
     *
     * @param conn connection to search on
     * @param unescapedDn DN of the entry
     * @param returnAttributes attributes to return
     * @param shouldFollowReferrals whether to follow referrals
     * @return the entry, or null if no entry exists for the DN or the search does not return exactly one entry
     * @throws LdapException if the search fails for any other reason, including a DN that the server rejects
     */
    public static LdapEntry lookup(
        final Connection conn,
        final String unescapedDn,
        final String[] returnAttributes,
        boolean shouldFollowReferrals
    ) throws LdapException {

        final List<LdapEntry> entries;
        try {
            entries = search(conn, unescapedDn, ALL, SearchScope.OBJECT, returnAttributes, shouldFollowReferrals);
        } catch (final LdapException e) {
            if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT) {
                return null;
            }
            throw e;
        }

        if (entries.size() == 1) {
            return entries.get(0);
        } else {
            return null;
        }
    }

    @VisibleForTesting
    static String escapeDn(String dn) throws InvalidNameException {
        final LdapName dnName = new LdapName(dn);
        final List<Rdn> escaped = new ArrayList<>(dnName.size());
        for (Rdn rdn : dnName.getRdns()) {
            escaped.add(new Rdn(rdn.getType(), escapeForwardSlash(rdn.getValue())));
        }
        return escapeControlCharacters(new LdapName(escaped).toString());
    }

    // Rdn does not escape control characters, so a \0A in a value would reach the server as a raw newline.
    private static String escapeControlCharacters(String dn) {
        final StringBuilder sb = new StringBuilder(dn.length());
        for (int i = 0; i < dn.length(); i++) {
            final char c = dn.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                sb.append(String.format(Locale.ROOT, "\\%02X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static Object escapeForwardSlash(Object input) {
        if (input != null && input instanceof String) {
            return ((String) input).replace("/", "\\2f");
        } else {
            return input;
        }
    }

}
