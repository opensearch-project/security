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

package com.amazon.dlic.auth.ldap.srv;

public class EmbeddedLDAPServer {

    LdapServer s = new LdapServer();

    public int applyLdif(final String... ldifFile) throws Exception {
        return s.start(ldifFile);
    }

    public void start() throws Exception {

    }

    public void stop() throws Exception {
        s.stop();
    }

    public int getLdapPort() {
        return s.getLdapPort();
    }

    public int getLdapsPort() {
        return s.getLdapsPort();
    }
}
