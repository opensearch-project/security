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

//Source: Apache Kerby project
//https://directory.apache.org/kerby/

import java.io.IOException;
import java.nio.file.Path;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
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

 private JaasKrbUtil() {
 }

 public static void setDebug(final boolean debug) {
     JaasKrbUtil.debug = debug;
 }

 public static Subject loginUsingPassword(final String principal, final String password) throws LoginException {
     final Set<Principal> principals = new HashSet<Principal>();
     principals.add(new KerberosPrincipal(principal));

     final Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());

     final Configuration conf = usePassword(principal);
     final String confName = "PasswordConf";
     final CallbackHandler callback = new KrbCallbackHandler(principal, password);
     final LoginContext loginContext = new LoginContext(confName, subject, callback, conf);
     loginContext.login();
     return loginContext.getSubject();
 }

 public static Subject loginUsingTicketCache(final String principal, final Path cachePath) throws LoginException {
     final Set<Principal> principals = new HashSet<Principal>();
     principals.add(new KerberosPrincipal(principal));

     final Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());

     final Configuration conf = useTicketCache(principal, cachePath);
     final String confName = "TicketCacheConf";
     final LoginContext loginContext = new LoginContext(confName, subject, null, conf);
     loginContext.login();
     return loginContext.getSubject();
 }

 public static Subject loginUsingKeytab(final Set<String> principalAsStrings, final Path keytabPath, final boolean initiator) throws LoginException {
     final Set<Principal> principals = new HashSet<Principal>();

     for(String p: principalAsStrings) {
         principals.add(new KerberosPrincipal(p));
     }


     final Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());

     final Configuration conf = useKeytab("*", keytabPath, initiator);
     final String confName = "KeytabConf";
     final LoginContext loginContext = new LoginContext(confName, subject, null, conf);
     loginContext.login();
     return loginContext.getSubject();
 }

 public static Configuration usePassword(final String principal) {
     return new PasswordJaasConf(principal);
 }

 public static Configuration useTicketCache(final String principal, final Path credentialPath) {
     return new TicketCacheJaasConf(principal, credentialPath);
 }

 public static Configuration useKeytab(final String principal, final Path keytabPath, final boolean initiator) {
     return new KeytabJaasConf(principal, keytabPath, initiator);
 }

 private static String getKrb5LoginModuleName() {
     return System.getProperty("java.vendor").contains("IBM") ? "com.ibm.security.auth.module.Krb5LoginModule"
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

         return new AppConfigurationEntry[] { new AppConfigurationEntry(getKrb5LoginModuleName(),
                 AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
     }
 }

 static class TicketCacheJaasConf extends Configuration {
     private final String principal;
     private final Path clientCredentialPath;

     public TicketCacheJaasConf(final String principal, final Path clientCredentialPath) {
         this.principal = principal;
         this.clientCredentialPath = clientCredentialPath;
     }

     @Override
     public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
         final Map<String, String> options = new HashMap<String, String>();
         options.put("principal", principal);
         options.put("storeKey", "false");
         options.put("doNotPrompt", "false");
         options.put("useTicketCache", "true");
         options.put("renewTGT", "true");
         options.put("refreshKrb5Config", "true");
         options.put("isInitiator", "true");
         options.put("ticketCache", clientCredentialPath.toAbsolutePath().toString());
         options.put("debug", String.valueOf(debug));

         return new AppConfigurationEntry[] { new AppConfigurationEntry(getKrb5LoginModuleName(),
                 AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
     }
 }

 static class PasswordJaasConf extends Configuration {
     private final String principal;

     public PasswordJaasConf(final String principal) {
         this.principal = principal;
     }

     @Override
     public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
         final Map<String, String> options = new HashMap<>();
         options.put("principal", principal);
         options.put("storeKey", "true");
         options.put("useTicketCache", "true");
         options.put("useKeyTab", "false");
         options.put("renewTGT", "true");
         options.put("refreshKrb5Config", "true");
         options.put("isInitiator", "true");
         options.put("debug", String.valueOf(debug));

         return new AppConfigurationEntry[] { new AppConfigurationEntry(getKrb5LoginModuleName(),
                 AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
     }
 }

 public static class KrbCallbackHandler implements CallbackHandler {
     private final String principal;
     private final String password;

     public KrbCallbackHandler(final String principal, final String password) {
         this.principal = principal;
         this.password = password;
     }

     @Override
     public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
         for (int i = 0; i < callbacks.length; i++) {
             if (callbacks[i] instanceof PasswordCallback) {
                 final PasswordCallback pc = (PasswordCallback) callbacks[i];
                 if (pc.getPrompt().contains(principal)) {
                     pc.setPassword(password.toCharArray());
                     break;
                 }
             }
         }
     }
 }

}
