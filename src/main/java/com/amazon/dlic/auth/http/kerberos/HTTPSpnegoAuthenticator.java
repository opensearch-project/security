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

package com.amazon.dlic.auth.http.kerberos;

import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import com.google.common.base.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.env.Environment;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.user.AuthCredentials;

import com.amazon.dlic.auth.http.kerberos.util.JaasKrbUtil;
import com.amazon.dlic.auth.http.kerberos.util.KrbConstants;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import static org.apache.http.HttpStatus.SC_UNAUTHORIZED;

public class HTTPSpnegoAuthenticator implements HTTPAuthenticator {

    private static final Oid[] KRB_OIDS = new Oid[] { KrbConstants.SPNEGO, KrbConstants.KRB5MECH };

    protected final Logger log = LogManager.getLogger(this.getClass());

    private boolean stripRealmFromPrincipalName;
    private Set<String> acceptorPrincipal;
    private Path acceptorKeyTabPath;

    @SuppressWarnings("removal")
    public HTTPSpnegoAuthenticator(final Settings settings, final Path configPath) {
        super();
        try {
            final Path configDir = new Environment(settings, configPath).configFile();
            final String krb5PathSetting = settings.get("plugins.security.kerberos.krb5_filepath");

            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            AccessController.doPrivileged(new PrivilegedAction<Void>() {

                @Override
                public Void run() {

                    try {
                        if (settings.getAsBoolean("krb_debug", false)) {
                            JaasKrbUtil.setDebug(true);
                            System.setProperty("sun.security.krb5.debug", "true");
                            System.setProperty("java.security.debug", "gssloginconfig,logincontext,configparser,configfile");
                            System.setProperty("sun.security.spnego.debug", "true");
                            System.out.println("Kerberos debug is enabled");
                            System.err.println("Kerberos debug is enabled");
                            log.info("Kerberos debug is enabled on stdout");
                        } else {
                            log.debug("Kerberos debug is NOT enabled");
                        }
                    } catch (Throwable e) {
                        log.error("Unable to enable krb_debug due to ", e);
                        log.debug("Unable to enable krb_debug due to " + ExceptionsHelper.stackTrace(e));
                    }

                    System.setProperty(KrbConstants.USE_SUBJECT_CREDS_ONLY_PROP, "false");

                    String krb5Path = krb5PathSetting;

                    if (!Strings.isNullOrEmpty(krb5Path)) {

                        if (Paths.get(krb5Path).isAbsolute()) {
                            log.debug("krb5_filepath: {}", krb5Path);
                            System.setProperty(KrbConstants.KRB5_CONF_PROP, krb5Path);
                        } else {
                            krb5Path = configDir.resolve(krb5Path).toAbsolutePath().toString();
                            log.debug("krb5_filepath (resolved from {}): {}", configDir, krb5Path);
                        }

                        System.setProperty(KrbConstants.KRB5_CONF_PROP, krb5Path);
                    } else {
                        if (Strings.isNullOrEmpty(System.getProperty(KrbConstants.KRB5_CONF_PROP))) {
                            System.setProperty(KrbConstants.KRB5_CONF_PROP, "/etc/krb5.conf");
                            log.debug("krb5_filepath (was not set or configured, set to default): /etc/krb5.conf");
                        }
                    }

                    stripRealmFromPrincipalName = settings.getAsBoolean("strip_realm_from_principal", true);
                    acceptorPrincipal = new HashSet<>(
                        settings.getAsList("plugins.security.kerberos.acceptor_principal", Collections.emptyList())
                    );
                    final String _acceptorKeyTabPath = settings.get("plugins.security.kerberos.acceptor_keytab_filepath");

                    if (acceptorPrincipal == null || acceptorPrincipal.size() == 0) {
                        log.error("acceptor_principal must not be null or empty. Kerberos authentication will not work");
                        acceptorPrincipal = null;
                    }

                    if (_acceptorKeyTabPath == null || _acceptorKeyTabPath.length() == 0) {
                        log.error(
                            "plugins.security.kerberos.acceptor_keytab_filepath must not be null or empty. Kerberos authentication will not work"
                        );
                        acceptorKeyTabPath = null;
                    } else {
                        acceptorKeyTabPath = configDir.resolve(settings.get("plugins.security.kerberos.acceptor_keytab_filepath"));

                        if (!Files.exists(acceptorKeyTabPath)) {
                            log.error(
                                "Unable to read keytab from {} - Maybe the file does not exist or is not readable. Kerberos authentication will not work",
                                acceptorKeyTabPath
                            );
                            acceptorKeyTabPath = null;
                        }
                    }

                    return null;
                }
            });

            log.debug("strip_realm_from_principal {}", stripRealmFromPrincipalName);
            log.debug("acceptor_principal {}", acceptorPrincipal);
            log.debug("acceptor_keytab_filepath {}", acceptorKeyTabPath);

        } catch (Throwable e) {
            log.error("Cannot construct HTTPSpnegoAuthenticator due to {}", e.getMessage(), e);
            log.error(
                "Please make sure you configured 'plugins.security.kerberos.acceptor_keytab_filepath' realtive to the ES config/ dir!"
            );
            throw e;
        }

    }

    @Override
    @SuppressWarnings("removal")
    public AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext threadContext) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        AuthCredentials creds = AccessController.doPrivileged(new PrivilegedAction<AuthCredentials>() {
            @Override
            public AuthCredentials run() {
                return extractCredentials0(request);
            }
        });

        return creds;
    }

    private AuthCredentials extractCredentials0(final SecurityRequest request) {

        if (acceptorPrincipal == null || acceptorKeyTabPath == null) {
            log.error("Missing acceptor principal or keytab configuration. Kerberos authentication will not work");
            return null;
        }

        Principal principal = null;
        final String authorizationHeader = request.header("Authorization");

        if (authorizationHeader != null) {
            if (!authorizationHeader.trim().toLowerCase().startsWith("negotiate ")) {
                log.warn("No 'Negotiate Authorization' header, send 401 and 'WWW-Authenticate Negotiate'");
                return null;
            } else {
                final byte[] decodedNegotiateHeader = Base64.getDecoder().decode(authorizationHeader.substring(10));

                GSSContext gssContext = null;
                byte[] outToken = null;

                try {

                    final Subject subject = JaasKrbUtil.loginUsingKeytab(acceptorPrincipal, acceptorKeyTabPath, false);

                    final GSSManager manager = GSSManager.getInstance();
                    final int credentialLifetime = GSSCredential.INDEFINITE_LIFETIME;

                    final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
                        @Override
                        public GSSCredential run() throws GSSException {
                            return manager.createCredential(null, credentialLifetime, KRB_OIDS, GSSCredential.ACCEPT_ONLY);
                        }
                    };
                    gssContext = manager.createContext(Subject.doAs(subject, action));

                    outToken = Subject.doAs(subject, new AcceptAction(gssContext, decodedNegotiateHeader));

                    if (outToken == null) {
                        log.warn("Ticket validation not successful, outToken is null");
                        return null;
                    }

                    principal = Subject.doAs(subject, new AuthenticateAction(log, gssContext, stripRealmFromPrincipalName));

                } catch (final LoginException e) {
                    log.error("Login exception due to", e);
                    return null;
                } catch (final GSSException e) {
                    log.error("Ticket validation not successful due to", e);
                    return null;
                } catch (final PrivilegedActionException e) {
                    final Throwable cause = e.getCause();
                    if (cause instanceof GSSException) {
                        log.info("Service login not successful due to", e);
                    } else {
                        log.error("Service login not successful due to", e);
                    }
                    return null;
                } finally {
                    if (gssContext != null) {
                        try {
                            gssContext.dispose();
                        } catch (final GSSException e) {
                            // Ignore
                        }
                    }
                }

                if (principal == null) {
                    return new AuthCredentials("_incomplete_", (Object) outToken);
                }

                final String username = ((SimpleUserPrincipal) principal).getName();

                if (username == null || username.length() == 0) {
                    log.error(
                        "Got empty or null user from kerberos. Normally this means that you acceptor principal {} does not match the server hostname",
                        acceptorPrincipal
                    );
                }

                return new AuthCredentials(username, (Object) outToken).markComplete();

            }
        } else {
            log.trace("No 'Authorization' header, send 401 and 'WWW-Authenticate Negotiate'");
            return null;
        }

    }

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest request, AuthCredentials creds) {
        final Map<String, String> headers = new HashMap<>();
        String responseBody = "";
        String contentType = null;
        SecurityResponse response;
        final String negotiateResponseBody = getNegotiateResponseBody();
        if (negotiateResponseBody != null) {
            responseBody = negotiateResponseBody;
            contentType = XContentType.JSON.mediaType();
        }

        if (creds == null || creds.getNativeCredentials() == null) {
            headers.put("WWW-Authenticate", "Negotiate");
        } else {
            headers.put("WWW-Authenticate", "Negotiate " + Base64.getEncoder().encodeToString((byte[]) creds.getNativeCredentials()));
        }

        if (contentType != null) {
            response = new SecurityResponse(SC_UNAUTHORIZED, headers, responseBody, contentType);
        } else {
            response = new SecurityResponse(SC_UNAUTHORIZED, headers, responseBody);
        }
        return Optional.of(response);
    }

    @Override
    public String getType() {
        return "spnego";
    }

    /**
     * This class gets a gss credential via a privileged action.
     */
    // borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static class AcceptAction implements PrivilegedExceptionAction<byte[]> {

        GSSContext gssContext;

        byte[] decoded;

        AcceptAction(final GSSContext context, final byte[] decodedToken) {
            this.gssContext = context;
            this.decoded = decodedToken;
        }

        @Override
        public byte[] run() throws GSSException {
            return gssContext.acceptSecContext(decoded, 0, decoded.length);
        }
    }

    // borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static class AuthenticateAction implements PrivilegedAction<Principal> {

        private final Logger logger;
        private final GSSContext gssContext;
        private final boolean strip;

        private AuthenticateAction(final Logger logger, final GSSContext gssContext, final boolean strip) {
            super();
            this.logger = logger;
            this.gssContext = gssContext;
            this.strip = strip;
        }

        @Override
        public Principal run() {
            return new SimpleUserPrincipal(getUsernameFromGSSContext(gssContext, strip, logger));
        }
    }

    // borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static String getUsernameFromGSSContext(final GSSContext gssContext, final boolean strip, final Logger logger) {
        if (gssContext.isEstablished()) {
            GSSName gssName = null;
            try {
                gssName = gssContext.getSrcName();
            } catch (final GSSException e) {
                logger.error("Unable to get src name from gss context", e);
            }

            if (gssName != null) {
                String name = gssName.toString();
                return stripRealmName(name, strip);
            } else {
                logger.error("GSS name is null");
            }
        } else {
            logger.error("GSS context not established");
        }

        return null;
    }

    private String getNegotiateResponseBody() {
        try {
            XContentBuilder negotiateResponseBody = XContentFactory.jsonBuilder();
            negotiateResponseBody.startObject();
            negotiateResponseBody.field("error");
            negotiateResponseBody.startObject();
            negotiateResponseBody.field("header");
            negotiateResponseBody.startObject();
            negotiateResponseBody.field("WWW-Authenticate", "Negotiate");
            negotiateResponseBody.endObject();
            negotiateResponseBody.endObject();
            negotiateResponseBody.endObject();
            return negotiateResponseBody.toString();
        } catch (Exception ex) {
            log.error("Can't construct response body", ex);
            return null;
        }
    }

    private static String stripRealmName(String name, boolean strip) {
        if (strip && name != null) {
            final int i = name.indexOf('@');
            if (i > 0) {
                // Zero so we don;t leave a zero length name
                name = name.substring(0, i);
            }
        }

        return name;
    }

    private static class SimpleUserPrincipal implements Principal, Serializable {

        private static final long serialVersionUID = -1;
        private final String username;

        SimpleUserPrincipal(final String username) {
            super();
            this.username = username;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((username == null) ? 0 : username.hashCode());
            return result;
        }

        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final SimpleUserPrincipal other = (SimpleUserPrincipal) obj;
            if (username == null) {
                if (other.username != null) {
                    return false;
                }
            } else if (!username.equals(other.username)) {
                return false;
            }
            return true;
        }

        @Override
        public String getName() {
            return this.username;
        }

        @Override
        public String toString() {
            final StringBuilder buffer = new StringBuilder();
            buffer.append("[principal: ");
            buffer.append(this.username);
            buffer.append("]");
            return buffer.toString();
        }
    }

}
