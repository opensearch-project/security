/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.dlic.auth.ldap.srv;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.net.BindException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.network.SocketUtils;
import com.google.common.io.CharStreams;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustStoreTrustManager;

final class LdapServer {
    private final static Logger LOG = LoggerFactory.getLogger(LdapServer.class);

    private static final int LOCK_TIMEOUT = 60;
    private static final TimeUnit TIME_UNIT = TimeUnit.SECONDS;

    private static final String LOCK_TIMEOUT_MSG = "Unable to obtain lock due to timeout after " + LOCK_TIMEOUT + " " + TIME_UNIT.toString();
    private static final String SERVER_NOT_STARTED = "The LDAP server is not started.";
    private static final String SERVER_ALREADY_STARTED = "The LDAP server is already started.";


    private InMemoryDirectoryServer server;
    private final AtomicBoolean isStarted = new AtomicBoolean(Boolean.FALSE);
    private final ReentrantLock serverStateLock = new ReentrantLock();

    private int ldapPort = -1;
    private int ldapsPort = -1;


    public LdapServer() {
    }

    public boolean isStarted() {
        return this.isStarted.get();
    }

    public int getLdapPort() {
        return ldapPort;
    }

    public int getLdapsPort() {
        return ldapsPort;
    }

    public int  start(String... ldifFiles) throws Exception {
        boolean hasLock = false;
        try {
            hasLock = serverStateLock.tryLock(LdapServer.LOCK_TIMEOUT, LdapServer.TIME_UNIT);
            if (hasLock) {
                int retVal = doStart(ldifFiles);
                this.isStarted.set(Boolean.TRUE);
                return retVal;
            } else {
                throw new IllegalStateException(LdapServer.LOCK_TIMEOUT_MSG);
            }
        } catch (InterruptedException ioe) {
            //lock interrupted
            LOG.error(ioe.getMessage(), ioe);
        } finally {
            if (hasLock) {
                serverStateLock.unlock();
            }
        }

        return -1;
    }

    private int doStart(String... ldifFiles) throws Exception {
        if (isStarted.get()) {
            throw new IllegalStateException(LdapServer.SERVER_ALREADY_STARTED);
        }
        return configureAndStartServer(ldifFiles);
    }

    private Collection<InMemoryListenerConfig> getInMemoryListenerConfigs() throws Exception {
        Collection<InMemoryListenerConfig> listenerConfigs = new ArrayList<InMemoryListenerConfig>();

        String serverKeyStorePath = FileHelper.getAbsoluteFilePathFromClassPath("ldap/node-0-keystore.jks").toFile().getAbsolutePath();
        final SSLUtil serverSSLUtil = new SSLUtil(
                new KeyStoreKeyManager(serverKeyStorePath, "changeit".toCharArray()), new TrustStoreTrustManager(serverKeyStorePath));
        //final SSLUtil clientSSLUtil = new SSLUtil(new TrustStoreTrustManager(serverKeyStorePath));

        ldapPort = SocketUtils.findAvailableTcpPort();
        ldapsPort = SocketUtils.findAvailableTcpPort();

        listenerConfigs.add(InMemoryListenerConfig.createLDAPConfig("ldap", null, ldapPort, serverSSLUtil.createSSLSocketFactory()));
        listenerConfigs.add(InMemoryListenerConfig.createLDAPSConfig("ldaps", ldapsPort, serverSSLUtil.createSSLServerSocketFactory()));

        return listenerConfigs;
    }

    private final String loadFile(final String file) throws IOException {
        String ldif;

        try (final Reader reader = new InputStreamReader(this.getClass().getResourceAsStream("/ldap/" + file),StandardCharsets.UTF_8)) {
            ldif = CharStreams.toString(reader);
        }


        ldif = ldif.replace("${hostname}", "localhost");
        ldif = ldif.replace("${port}", String.valueOf(ldapPort));
        return ldif;

    }

    private synchronized int configureAndStartServer(String... ldifFiles) throws Exception {
        Collection<InMemoryListenerConfig> listenerConfigs = getInMemoryListenerConfigs();

        Schema schema = Schema.getDefaultStandardSchema();

        final String rootObjectDN = "o=TEST";
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(new DN(rootObjectDN));

        config.setSchema(schema);  //schema can be set on the rootDN too, per javadoc.
        config.setListenerConfigs(listenerConfigs);
        config.setEnforceAttributeSyntaxCompliance(false);
        config.setEnforceSingleStructuralObjectClass(false);

        //config.setLDAPDebugLogHandler(DEBUG_HANDLER);
        //config.setAccessLogHandler(DEBUG_HANDLER);
        //config.addAdditionalBindCredentials(configuration.getBindDn(), configuration.getPassword());

        server = new InMemoryDirectoryServer(config);

        try {
            /* Clear entries from server. */
            server.clear();
            server.startListening();
            return loadLdifFiles(ldifFiles);
        } catch (LDAPException ldape) {
            if (ldape.getMessage().contains("java.net.BindException")) {
                throw new BindException(ldape.getMessage());
            }
            throw ldape;
        }

    }

    public void stop() {
        boolean hasLock = false;
        try {
            hasLock = serverStateLock.tryLock(LdapServer.LOCK_TIMEOUT, LdapServer.TIME_UNIT);
            if (hasLock) {
                if (!isStarted.get()) {
                    throw new IllegalStateException(LdapServer.SERVER_NOT_STARTED);
                }
                LOG.info("Shutting down in-Memory Ldap Server.");
                server.shutDown(true);
            } else {
                throw new IllegalStateException(LdapServer.LOCK_TIMEOUT_MSG);
            }
        } catch (InterruptedException ioe) {
            //lock interrupted
            LOG.debug(ExceptionUtils.getStackTrace(ioe));
        } finally {
            if (hasLock) {
                serverStateLock.unlock();
            }
        }
    }

    private int loadLdifFiles(String... ldifFiles) throws Exception {
        int ldifLoadCount = 0;
        for (String ldif : ldifFiles) {
            ldifLoadCount++;
            try (LDIFReader r = new LDIFReader(new BufferedReader(new StringReader(loadFile(ldif))))){
                Entry entry = null;
                while ((entry = r.readEntry()) != null) {
                    server.add(entry);
                    ldifLoadCount++;
                }
            } catch(Exception e) {
                LOG.error(e.toString(), e);
                throw e;
            }
        }
        return ldifLoadCount;
    }

    /* private static class DebugHandler extends Handler {
        private final static Logger LOG = LoggerFactory.getLogger(DebugHandler.class);

        @Override
        public void publish(LogRecord logRecord) {
           //LOG.debug(ToStringBuilder.reflectionToString(logRecord, ToStringStyle.MULTI_LINE_STYLE));
        }

        @Override
        public void flush() {

        }

        @Override
        public void close() throws SecurityException {

        }
    }

    private static final DebugHandler DEBUG_HANDLER = new DebugHandler();
    */
}
