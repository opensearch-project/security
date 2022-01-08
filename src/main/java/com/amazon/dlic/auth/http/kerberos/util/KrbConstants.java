/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
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

 private KrbConstants() {
 }

}
