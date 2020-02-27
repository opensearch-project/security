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


public class EmbeddedLDAPServer {

    LdapServer s = new LdapServer();

    /*private final Logger log = LoggerFactory.getLogger(EmbeddedLDAPServer.class);

    private DirectoryService directoryService;
    private LdapServer ldapServer;
    public final static int ldapPort = 40622;
    public final static int ldapsPort = 40623;

    private SchemaManager schemaManager;

    public static void main(final String[] args) throws Exception {
        new EmbeddedLDAPServer().start();
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
    public void start() throws Exception {

        directoryService = DSAnnotationProcessor.getDirectoryService();
        schemaManager = directoryService.getSchemaManager();
        final CreateLdapServer cl = (CreateLdapServer) AnnotationUtils.getInstance(CreateLdapServer.class);
        ldapServer = ServerAnnotationProcessor.instantiateLdapServer(cl, directoryService);

        ldapServer.setKeystoreFile(FileHelper.getAbsoluteFilePathFromClassPath("ldap/node-0-keystore.jks").toFile().getAbsolutePath());
        ldapServer.setCertificatePassword("changeit");

        // ldapServer.setEnabledCipherSuites(Arrays.asList(SecurityUtil.ENABLED_SSL_CIPHERS));

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

        directoryService.shutdown();
        ldapServer.stop();

        log.debug("LDAP stopped");

    }

    protected final String loadFile(final String file) throws IOException {
        final StringWriter sw = new StringWriter();
        IOUtils.copy(this.getClass().getResourceAsStream("/ldap/" + file), sw);
        return sw.toString();
    }

    public int applyLdif(final String ldifFile) throws Exception {

        String ldif = loadFile(ldifFile);
        ldif = ldif.replace("${hostname}", "localhost");
        ldif = ldif.replace("${port}", String.valueOf(ldapPort));

        int i = 0;
        for (final LdifEntry ldifEntry : new LdifReader(new StringReader(ldif))) {
            directoryService.getAdminSession().add(new DefaultEntry(schemaManager, ldifEntry.getEntry()));
            log.trace(ldifEntry.toString());
            i++;
        }

        return i;
    }*/

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