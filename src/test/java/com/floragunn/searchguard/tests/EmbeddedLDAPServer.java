/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.tests;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.directory.api.ldap.model.constants.SupportedSaslMechanisms;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.annotations.SaslMechanism;
import org.apache.directory.server.core.annotations.AnnotationUtils;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.factory.DSAnnotationProcessor;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.factory.ServerAnnotationProcessor;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KerberosKeyFactory;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.ldap.handlers.sasl.cramMD5.CramMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.digestMD5.DigestMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.gssapi.GssapiMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.ntlm.NtlmMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.plain.PlainMechanismHandler;
import org.apache.directory.shared.kerberos.KerberosTime;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.components.EncryptionKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.floragunn.searchguard.AbstractUnitTest;
import com.floragunn.searchguard.util.SecurityUtil;

public class EmbeddedLDAPServer {

    private final Logger log = LoggerFactory.getLogger(EmbeddedLDAPServer.class);

    private DirectoryService directoryService;
    private LdapServer ldapServer;
    private KdcServer kdcServer;
    public final static int ldapPort = 40622;
    public final static int ldapsPort = 40623;
    private final static int kdcPort = 40624;

    private SchemaManager schemaManager;

    public void createKeytab(final String principalName, final String passPhrase, final File keytabFile) throws IOException {
        final KerberosTime timeStamp = new KerberosTime();
        final int principalType = 1; // KRB5_NT_PRINCIPAL

        final Keytab keytab = keytabFile.exists() ? Keytab.read(keytabFile) : Keytab.getInstance();

        final List<KeytabEntry> entries = new ArrayList<KeytabEntry>();
        for (final Map.Entry<EncryptionType, EncryptionKey> keyEntry : KerberosKeyFactory.getKerberosKeys(principalName, passPhrase)
                .entrySet()) {
            final EncryptionKey key = keyEntry.getValue();
            final byte keyVersion = (byte) key.getKeyVersion();
            entries.add(new KeytabEntry(principalName, principalType, timeStamp, keyVersion, key));
        }

        entries.addAll(keytab.getEntries());

        keytab.setEntries(entries);
        keytab.write(keytabFile);
        log.debug("Keytab with " + keytab.getEntries().size() + " entries written to " + keytabFile.getAbsolutePath());
    }

    @CreateDS(name = "ExampleComDS", allowAnonAccess = true, partitions = { @CreatePartition(name = "examplecom", suffix = "o=TEST", contextEntry = @ContextEntry(entryLdif = "dn: o=TEST\n"
            + "dc: TEST\n" + "objectClass: top\n" + "objectClass: domain\n\n"), indexes = { @CreateIndex(attribute = "objectClass"),
        @CreateIndex(attribute = "dc"), @CreateIndex(attribute = "ou") }) }, additionalInterceptors = { KeyDerivationInterceptor.class })
    @CreateLdapServer(allowAnonymousAccess = true, transports = {
            @CreateTransport(protocol = "LDAP", address = "localhost", port = ldapPort),
            @CreateTransport(protocol = "LDAPS", address = "localhost", port = ldapsPort) },

            saslHost = "localhost", saslPrincipal = "ldap/localhost@EXAMPLE.COM", saslMechanisms = {
            @SaslMechanism(name = SupportedSaslMechanisms.PLAIN, implClass = PlainMechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.CRAM_MD5, implClass = CramMd5MechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.DIGEST_MD5, implClass = DigestMd5MechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.GSSAPI, implClass = GssapiMechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.NTLM, implClass = NtlmMechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.GSS_SPNEGO, implClass = NtlmMechanismHandler.class) }, extendedOpHandlers = { StartTlsHandler.class }

            )
    @CreateKdcServer(primaryRealm = "example.com", kdcPrincipal = "krbtgt/example.com@example.com", searchBaseDn = "o=TEST",
    //maxTicketLifetime = 1000,
    //maxRenewableLifetime = 2000,
    transports = { @CreateTransport(protocol = "TCP", port = kdcPort), @CreateTransport(protocol = "UDP", port = kdcPort) })
    public void start() throws Exception {

        directoryService = DSAnnotationProcessor.getDirectoryService();
        kdcServer = ServerAnnotationProcessor.getKdcServer(directoryService, kdcPort);
        kdcServer.getConfig().setPaEncTimestampRequired(false);
        schemaManager = directoryService.getSchemaManager();
        final CreateLdapServer cl = (CreateLdapServer) AnnotationUtils.getInstance(CreateLdapServer.class);
        ldapServer = ServerAnnotationProcessor.instantiateLdapServer(cl, directoryService);

        ldapServer.setKeystoreFile(SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardKS.jks").getAbsolutePath());
        ldapServer.setCertificatePassword("changeit");
        ldapServer.setEnabledCipherSuites(Arrays.asList(SecurityUtil.ENABLED_SSL_CIPHERS));

        if (ldapServer.isStarted()) {
            throw new IllegalStateException("Service already running");
        }

        ldapServer.start();

        log.debug("LDAP started");
    }

    public void stop() throws Exception {

        if (!ldapServer.isStarted()) {
            throw new IllegalStateException("Service is not running");
        }

        kdcServer.stop();
        directoryService.shutdown();
        ldapServer.stop();

        log.debug("LDAP stopped");

    }

    public int applyLdif(final File ldifFile) throws Exception {

        final File newLdif = new File("target/tmp/" + ldifFile.getName());
        String ldif = FileUtils.readFileToString(ldifFile);
        ldif = ldif.replace("${hostname}", AbstractUnitTest.getNonLocalhostAddress());
        FileUtils.write(newLdif, ldif);

        int i = 0;
        for (final LdifEntry ldifEntry : new LdifReader(newLdif)) {
            directoryService.getAdminSession().add(new DefaultEntry(schemaManager, ldifEntry.getEntry()));
            log.trace(ldifEntry.toString());
            i++;
        }

        return i;
    }
}