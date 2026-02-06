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
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.opensearch.secure_sm.AccessController;

import org.ldaptive.ConnectionFactory;
import org.ldaptive.FilterTemplate;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResponse;
import org.ldaptive.SearchScope;
import org.ldaptive.handler.SearchResultHandler;
import org.ldaptive.referral.FollowSearchReferralHandler;

public class LdapHelper {

    private static FilterTemplate ALL = FilterTemplate.builder().filter("(objectClass=*)").build();

    public static List<LdapEntry> search(
        final ConnectionFactory connectionFactory,
        final String unescapedDn,
        FilterTemplate filter,
        final SearchScope searchScope,
        final String[] returnAttributes,
        boolean shouldFollowReferrals
    ) throws LdapException {

        try {
            final String baseDn = escapeDn(unescapedDn);
            return AccessController.doPrivilegedChecked(() -> {
                final List<LdapEntry> entries = new ArrayList<>();

                SearchRequest request = SearchRequest.builder()
                    .dn(baseDn)
                    .filter(filter)
                    .scope(searchScope)
                    .returnAttributes(returnAttributes)
                    .build();

                SearchOperation search = new SearchOperation(connectionFactory);

                if (shouldFollowReferrals) {
                    search.setSearchResultHandlers(new SearchResultHandler[] { new FollowSearchReferralHandler() });
                }

                final SearchResponse response = search.execute(request);
                entries.addAll(response.getEntries());

                return entries;
            });
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }
    }

    public static LdapEntry lookup(
        final ConnectionFactory connectionFactory,
        final String unescapedDn,
        final String[] returnAttributes,
        boolean shouldFollowReferrals
    ) throws LdapException {

        final List<LdapEntry> entries = search(
            connectionFactory,
            unescapedDn,
            ALL,
            SearchScope.OBJECT,
            returnAttributes,
            shouldFollowReferrals
        );

        if (entries.size() == 1) {
            return entries.get(0);
        } else {
            return null;
        }
    }

    private static String escapeDn(String dn) throws InvalidNameException {
        // LdapName handles proper DN escaping - just return the normalized form
        final LdapName dnName = new LdapName(dn);
        return dnName.toString();
    }

}
