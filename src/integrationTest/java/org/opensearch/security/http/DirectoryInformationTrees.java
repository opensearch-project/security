/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.http;

import org.opensearch.test.framework.ldap.LdifBuilder;
import org.opensearch.test.framework.ldap.LdifData;

class DirectoryInformationTrees {

    public static final String DN_PEOPLE_TEST_ORG = "ou=people,o=test.org";
    public static final String DN_OPEN_SEARCH_PEOPLE_TEST_ORG = "cn=Open Search,ou=people,o=test.org";
    public static final String DN_CHRISTPHER_PEOPLE_TEST_ORG = "cn=Christpher,ou=people,o=test.org";
    public static final String DN_KIRK_PEOPLE_TEST_ORG = "cn=Kirk,ou=people,o=test.org";
    public static final String DN_CAPTAIN_SPOCK_PEOPLE_TEST_ORG = "cn=Captain Spock,ou=people,o=test.org";
    public static final String DN_LEONARD_PEOPLE_TEST_ORG = "cn=Leonard,ou=people,o=test.org";
    public static final String DN_JEAN_PEOPLE_TEST_ORG = "cn=Jean,ou=people,o=test.org";
    public static final String DN_GROUPS_TEST_ORG = "ou=groups,o=test.org";
    public static final String DN_BRIDGE_GROUPS_TEST_ORG = "cn=bridge,ou=groups,o=test.org";

    public static final String USER_KIRK = "kirk";
    public static final String PASSWORD_KIRK = "kirk-secret";
    public static final String USER_SPOCK = "spock";
    public static final String PASSWORD_SPOCK = "spocksecret";
    public static final String USER_OPENS = "opens";
    public static final String PASSWORD_OPEN_SEARCH = "open_search-secret";
    public static final String USER_JEAN = "jean";
    public static final String PASSWORD_JEAN = "jeansecret";
    public static final String USER_LEONARD = "leonard";
    public static final String PASSWORD_LEONARD = "Leonard-secret";
    public static final String PASSWORD_CHRISTPHER = "christpher_secret";

    public static final String CN_GROUP_ADMIN = "admin";
    public static final String CN_GROUP_CREW = "crew";
    public static final String CN_GROUP_BRIDGE = "bridge";

    public static final String USER_SEARCH = "(uid={0})";
    public static final String USERNAME_ATTRIBUTE = "uid";

    static final LdifData LDIF_DATA = new LdifBuilder().root("o=test.org")
        .dc("TEST")
        .classes("top", "domain")
        .newRecord(DN_PEOPLE_TEST_ORG)
        .ou("people")
        .classes("organizationalUnit", "top")
        .newRecord(DN_OPEN_SEARCH_PEOPLE_TEST_ORG)
        .classes("inetOrgPerson")
        .cn("Open Search")
        .sn("Search")
        .uid(USER_OPENS)
        .userPassword(PASSWORD_OPEN_SEARCH)
        .mail("open.search@example.com")
        .ou("Human Resources")
        .newRecord(DN_CAPTAIN_SPOCK_PEOPLE_TEST_ORG)
        .classes("inetOrgPerson")
        .cn("Captain Spock")
        .sn(USER_SPOCK)
        .uid(USER_SPOCK)
        .userPassword(PASSWORD_SPOCK)
        .mail("spock@example.com")
        .ou("Human Resources")
        .newRecord(DN_KIRK_PEOPLE_TEST_ORG)
        .classes("inetOrgPerson")
        .cn("Kirk")
        .sn("Kirk")
        .uid(USER_KIRK)
        .userPassword(PASSWORD_KIRK)
        .mail("spock@example.com")
        .ou("Human Resources")
        .newRecord(DN_CHRISTPHER_PEOPLE_TEST_ORG)
        .classes("inetOrgPerson")
        .cn("Christpher")
        .sn("Christpher")
        .uid("christpher")
        .userPassword(PASSWORD_CHRISTPHER)
        .mail("christpher@example.com")
        .ou("Human Resources")
        .newRecord(DN_LEONARD_PEOPLE_TEST_ORG)
        .classes("inetOrgPerson")
        .cn("Leonard")
        .sn("Leonard")
        .uid(USER_LEONARD)
        .userPassword(PASSWORD_LEONARD)
        .mail("leonard@example.com")
        .ou("Human Resources")
        .newRecord(DN_JEAN_PEOPLE_TEST_ORG)
        .classes("inetOrgPerson")
        .cn("Jean")
        .sn("Jean")
        .uid(USER_JEAN)
        .userPassword(PASSWORD_JEAN)
        .mail("jean@example.com")
        .ou("Human Resources")
        .newRecord(DN_GROUPS_TEST_ORG)
        .ou("groups")
        .cn("groupsRoot")
        .classes("groupofuniquenames", "top")
        .newRecord("cn=admin,ou=groups,o=test.org")
        .ou("groups")
        .cn(CN_GROUP_ADMIN)
        .uniqueMember(DN_KIRK_PEOPLE_TEST_ORG)
        .classes("groupofuniquenames", "top")
        .newRecord("cn=crew,ou=groups,o=test.org")
        .ou("groups")
        .cn(CN_GROUP_CREW)
        .uniqueMember(DN_CAPTAIN_SPOCK_PEOPLE_TEST_ORG)
        .uniqueMember(DN_CHRISTPHER_PEOPLE_TEST_ORG)
        .uniqueMember(DN_BRIDGE_GROUPS_TEST_ORG)
        .classes("groupofuniquenames", "top")
        .newRecord(DN_BRIDGE_GROUPS_TEST_ORG)
        .ou("groups")
        .cn(CN_GROUP_BRIDGE)
        .uniqueMember(DN_JEAN_PEOPLE_TEST_ORG)
        .classes("groupofuniquenames", "top")
        .buildRecord()
        .buildLdif();
}
