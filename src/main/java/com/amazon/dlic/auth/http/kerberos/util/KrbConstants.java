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

package com.amazon.dlic.auth.http.kerberos.util;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

public final class KrbConstants {

    static {
        Oid spnegoTmp = null;
        Oid krbTmp = null;
        try {
            spnegoTmp = new Oid("1.3.6.1.5.5.2");
            krbTmp = new Oid("1.2.840.113554.1.2.2");
        } catch (final GSSException e) {

        }
        SPNEGO = spnegoTmp;
        KRB5MECH = krbTmp;
    }

    public static final Oid SPNEGO;
    public static final Oid KRB5MECH;
    public static final String KRB5_CONF_PROP = "java.security.krb5.conf";
    public static final String JAAS_LOGIN_CONF_PROP = "java.security.auth.login.config";
    public static final String USE_SUBJECT_CREDS_ONLY_PROP = "javax.security.auth.useSubjectCredsOnly";
    public static final String NEGOTIATE = "Negotiate";
    public static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private KrbConstants() {}

}
