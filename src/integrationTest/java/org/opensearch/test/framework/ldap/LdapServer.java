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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.BindException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.cluster.SocketUtils;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.ssl.SSLUtil;

/**
* Based on class com.amazon.dlic.auth.ldap.srv.LdapServer from older tests
*/
final class LdapServer {
    private static final Logger log = LogManager.getLogger(LdapServer.class);

    private static final int LOCK_TIMEOUT = 60;
    private static final TimeUnit TIME_UNIT = TimeUnit.SECONDS;

    private static final String LOCK_TIMEOUT_MSG = "Unable to obtain lock due to timeout after "
        + LOCK_TIMEOUT
        + " "
        + TIME_UNIT.toString();
    private static final String SERVER_NOT_STARTED = "The LDAP server is not started.";
    private static final String SERVER_ALREADY_STARTED = "The LDAP server is already started.";

    private final CertificateData trustAnchor;

    private final CertificateData ldapCertificate;

    private InMemoryDirectoryServer server;
    private final AtomicBoolean isStarted = new AtomicBoolean(Boolean.FALSE);
    private final ReentrantLock serverStateLock = new ReentrantLock();

    private int ldapNonTlsPort = -1;
    private int ldapTlsPort = -1;

    public LdapServer(CertificateData trustAnchor, CertificateData ldapCertificate) {
        this.trustAnchor = trustAnchor;
        this.ldapCertificate = ldapCertificate;
    }

    public boolean isStarted() {
        return this.isStarted.get();
    }

    public int getLdapNonTlsPort() {
        return ldapNonTlsPort;
    }

    public int getLdapsTlsPort() {
        return ldapTlsPort;
    }

    public void start(LdifData ldifData) throws Exception {
        Objects.requireNonNull(ldifData, "Ldif data is required");
        boolean hasLock = false;
        try {
            hasLock = serverStateLock.tryLock(LdapServer.LOCK_TIMEOUT, LdapServer.TIME_UNIT);
            if (hasLock) {
                doStart(ldifData);
                this.isStarted.set(Boolean.TRUE);
            } else {
                throw new IllegalStateException(LdapServer.LOCK_TIMEOUT_MSG);
            }
        } catch (InterruptedException ioe) {
            // lock interrupted
            log.error("LDAP server start lock interrupted", ioe);
            throw ioe;
        } finally {
            if (hasLock) {
                serverStateLock.unlock();
            }
        }
    }

    private void doStart(LdifData ldifData) throws Exception {
        if (isStarted.get()) {
            throw new IllegalStateException(LdapServer.SERVER_ALREADY_STARTED);
        }
        configureAndStartServer(ldifData);
    }

    private Collection<InMemoryListenerConfig> getInMemoryListenerConfigs() throws Exception {
        KeyStore keyStore = createEmptyKeyStore();
        addLdapCertificatesToKeystore(keyStore);
        final SSLUtil sslUtil = new SSLUtil(createKeyManager(keyStore), createTrustManagers(keyStore));

        ldapNonTlsPort = SocketUtils.findAvailableTcpPort();
        ldapTlsPort = SocketUtils.findAvailableTcpPort();

        Collection<InMemoryListenerConfig> listenerConfigs = new ArrayList<>();
        listenerConfigs.add(InMemoryListenerConfig.createLDAPConfig("ldap", null, ldapNonTlsPort, sslUtil.createSSLSocketFactory()));
        listenerConfigs.add(InMemoryListenerConfig.createLDAPSConfig("ldaps", ldapTlsPort, sslUtil.createSSLServerSocketFactory()));
        return listenerConfigs;
    }

    private static KeyManager[] createKeyManager(KeyStore keyStore) throws NoSuchAlgorithmException, KeyStoreException,
        UnrecoverableKeyException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, null);
        return keyManagerFactory.getKeyManagers();
    }

    private static TrustManager[] createTrustManagers(KeyStore keyStore) throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return trustManagerFactory.getTrustManagers();
    }

    private void addLdapCertificatesToKeystore(KeyStore keyStore) throws KeyStoreException {
        keyStore.setCertificateEntry("trustAnchor", trustAnchor.certificate());
        keyStore.setKeyEntry("ldap-key", ldapCertificate.getKey(), null, new Certificate[] { ldapCertificate.certificate() });
    }

    private static KeyStore createEmptyKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        return keyStore;
    }

    private synchronized void configureAndStartServer(LdifData ldifData) throws Exception {
        Collection<InMemoryListenerConfig> listenerConfigs = getInMemoryListenerConfigs();

        Schema schema = Schema.getDefaultStandardSchema();

        final String rootObjectDN = ldifData.getRootDistinguishedName();
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(new DN(rootObjectDN));

        config.setSchema(schema);  // schema can be set on the rootDN too, per javadoc.
        config.setListenerConfigs(listenerConfigs);
        config.setEnforceAttributeSyntaxCompliance(false);
        config.setEnforceSingleStructuralObjectClass(false);

        server = new InMemoryDirectoryServer(config);

        try {
            /* Clear entries from server. */
            server.clear();
            server.startListening();
            loadLdifData(ldifData);
        } catch (LDAPException ldape) {
            if (ldape.getMessage().contains("java.net.BindException")) {
                throw new BindException(ldape.getMessage());
            }
            throw ldape;
        }

    }

    public void stop() throws InterruptedException {
        boolean hasLock = false;
        try {
            hasLock = serverStateLock.tryLock(LdapServer.LOCK_TIMEOUT, LdapServer.TIME_UNIT);
            if (hasLock) {
                if (!isStarted.get()) {
                    throw new IllegalStateException(LdapServer.SERVER_NOT_STARTED);
                }
                log.info("Shutting down in-Memory Ldap Server.");
                server.shutDown(true);
            } else {
                throw new IllegalStateException(LdapServer.LOCK_TIMEOUT_MSG);
            }
        } catch (InterruptedException ioe) {
            // lock interrupted
            log.error("Canot stop LDAP server due to interruption", ioe);
            throw ioe;
        } finally {
            if (hasLock) {
                serverStateLock.unlock();
            }
        }
    }

    private void loadLdifData(LdifData ldifData) throws Exception {
        try (LDIFReader r = new LDIFReader(new BufferedReader(new StringReader(ldifData.getContent())))) {
            Entry entry;
            while ((entry = r.readEntry()) != null) {
                server.add(entry);
            }
        } catch (Exception e) {
            log.error("Cannot load data into LDAP server", e);
            throw e;
        }
    }
}
