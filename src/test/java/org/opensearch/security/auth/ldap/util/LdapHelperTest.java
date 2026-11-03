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

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class LdapHelperTest {

    @Test
    public void escapeDnKeepsEscapedNewline() throws Exception {
        assertThat(
            LdapHelper.escapeDn("CN=SCA-LDAP\\0ACNF:1234,OU=Groups,DC=example,DC=com"),
            equalTo("CN=SCA-LDAP\\0ACNF:1234,OU=Groups,DC=example,DC=com")
        );
    }

    @Test
    public void escapeDnLeavesPlainDnUnchanged() throws Exception {
        assertThat(LdapHelper.escapeDn("cn=rolemo4,ou=groups,o=TEST"), equalTo("cn=rolemo4,ou=groups,o=TEST"));
    }
}
