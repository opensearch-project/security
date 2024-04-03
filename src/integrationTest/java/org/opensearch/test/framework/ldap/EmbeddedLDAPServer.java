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

package org.opensearch.test.framework.ldap;

import java.util.Objects;

import org.junit.rules.ExternalResource;

import org.opensearch.test.framework.certificate.CertificateData;

public class EmbeddedLDAPServer extends ExternalResource {

    private final LdapServer server;

    private final LdifData ldifData;

    public EmbeddedLDAPServer(CertificateData trustAnchor, CertificateData ldapCertificate, LdifData ldifData) {
        this.ldifData = Objects.requireNonNull(ldifData, "Ldif data is required");
        this.server = new LdapServer(trustAnchor, ldapCertificate);
    }

    @Override
    protected void before() {
        try {
            server.start(ldifData);
        } catch (Exception e) {
            throw new RuntimeException("Cannot start ldap server", e);
        }
    }

    @Override
    protected void after() {
        try {
            server.stop();
        } catch (InterruptedException e) {
            throw new RuntimeException("Cannot stop LDAP server.", e);
        }
    }

    public int getLdapNonTlsPort() {
        return server.getLdapNonTlsPort();
    }

    public int getLdapTlsPort() {
        return server.getLdapsTlsPort();
    }
}
