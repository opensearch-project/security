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

package org.opensearch.security.auth.http.kerberos.util;

//Source: Apache Kerby project
//https://directory.apache.org/kerby/

import java.nio.file.Path;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
* JAAS utilities for Kerberos login.
*/
public final class JaasKrbUtil {

    private static boolean debug = false;

    private JaasKrbUtil() {}

    public static void setDebug(final boolean debug) {
        JaasKrbUtil.debug = debug;
    }

    public static Subject loginUsingKeytab(final Set<String> principalAsStrings, final Path keytabPath, final boolean initiator)
        throws LoginException {
        final Set<Principal> principals = new HashSet<Principal>();

        for (String p : principalAsStrings) {
            principals.add(new KerberosPrincipal(p));
        }

        final Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());

        final Configuration conf = useKeytab("*", keytabPath, initiator);
        final String confName = "KeytabConf";
        final LoginContext loginContext = new LoginContext(confName, subject, null, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    public static Configuration useKeytab(final String principal, final Path keytabPath, final boolean initiator) {
        return new KeytabJaasConf(principal, keytabPath, initiator);
    }

    private static String getKrb5LoginModuleName() {
        return System.getProperty("java.vendor").contains("IBM")
            ? "com.ibm.security.auth.module.Krb5LoginModule"
            : "com.sun.security.auth.module.Krb5LoginModule";
    }

    static class KeytabJaasConf extends Configuration {
        private final String principal;
        private final Path keytabPath;
        private final boolean initiator;

        public KeytabJaasConf(final String principal, final Path keytab, final boolean initiator) {
            this.principal = principal;
            this.keytabPath = keytab;
            this.initiator = initiator;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
            final Map<String, String> options = new HashMap<String, String>();
            options.put("keyTab", keytabPath.toAbsolutePath().toString());
            options.put("principal", principal);
            options.put("useKeyTab", "true");
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            options.put("renewTGT", "false");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", String.valueOf(initiator));
            options.put("debug", String.valueOf(debug));

            return new AppConfigurationEntry[] {
                new AppConfigurationEntry(getKrb5LoginModuleName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
        }
    }

}
