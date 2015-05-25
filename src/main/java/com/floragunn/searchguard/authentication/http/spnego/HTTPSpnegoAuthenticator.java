/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt) and Apache Software Foundation
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
 * Some code of this file is borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
 * 
 */

package com.floragunn.searchguard.authentication.http.spnego;

import java.io.Serializable;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.xml.bind.DatatypeConverter;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authentication.http.HTTPAuthenticator;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

public class HTTPSpnegoAuthenticator implements HTTPAuthenticator {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;
    private final String loginContextName;
    private final boolean strip;

    @Inject
    public HTTPSpnegoAuthenticator(final Settings settings) {
        this.settings = settings;

        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

        SecurityUtil.setSystemPropertyToAbsoluteFile("java.security.auth.login.config",
                settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_FILEPATH));
        SecurityUtil.setSystemPropertyToAbsoluteFile("java.security.krb5.conf",
                settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_SPNEGO_KRB5_CONFIG_FILEPATH));

        this.loginContextName = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_NAME,
                "com.sun.security.jgss.krb5.accept");
        this.strip = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUTHENTICATION_SPNEGO_STRIP_REALM, true);

    }

    //some of this is borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    @Override
    public User authenticate(final RestRequest request, final RestChannel channel, final AuthenticationBackend backend,
            final Authorizator authorizator) throws AuthException {

        String authorizationHeader = request.header("Authorization");
        Principal principal = null;

        if (authorizationHeader != null) {

            if (!authorizationHeader.trim().toLowerCase().startsWith("negotiate ")) {
                throw new AuthException("Bad 'Authorization' header");
            } else {

                byte[] decodedNegotiateHeader = DatatypeConverter.parseBase64Binary(authorizationHeader.substring(10));

                LoginContext lc = null;
                GSSContext gssContext = null;
                byte[] outToken = null;
                try {
                    try {
                        lc = new LoginContext(loginContextName);
                        lc.login();
                    } catch (final LoginException e) {
                        log.error("Unable to login due to {}", e, e.toString());
                        throw new AuthException(e);
                    }

                    final Subject subject = lc.getSubject();

                    final GSSManager manager = GSSManager.getInstance();
                    final int credentialLifetime = GSSCredential.INDEFINITE_LIFETIME;

                    final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
                        @Override
                        public GSSCredential run() throws GSSException {
                            return manager.createCredential(null, credentialLifetime, new Oid("1.3.6.1.5.5.2"), GSSCredential.ACCEPT_ONLY);
                        }
                    };
                    gssContext = manager.createContext(Subject.doAs(subject, action));

                    outToken = Subject.doAs(lc.getSubject(), new AcceptAction(gssContext, decodedNegotiateHeader));

                    if (outToken == null) {
                        log.trace("Ticket validation not successful");
                        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
                        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Negotiate");
                        channel.sendResponse(wwwAuthenticateResponse);
                        return null;
                    }

                    principal = Subject.doAs(subject, new AuthenticateAction(this, gssContext, strip));

                } catch (final GSSException e) {
                    log.trace("Ticket validation not successful due to {}", e);
                    final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
                    wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Negotiate");
                    channel.sendResponse(wwwAuthenticateResponse);
                    return null;
                } catch (final PrivilegedActionException e) {
                    final Throwable cause = e.getCause();
                    if (cause instanceof GSSException) {
                        log.trace("Service login not successful due to {}", e);
                    } else {
                        log.error("Service login not successful due to {}", e.toString(), e);
                    }
                    final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
                    wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Negotiate");
                    channel.sendResponse(wwwAuthenticateResponse);
                    return null;
                } finally {
                    if (gssContext != null) {
                        try {
                            gssContext.dispose();
                        } catch (final GSSException e) {
                            // Ignore
                        }
                    }
                    if (lc != null) {
                        try {
                            lc.logout();
                        } catch (final LoginException e) {
                            // Ignore
                        }
                    }
                }

                if (principal == null) {

                    final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
                    wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Negotiate " + DatatypeConverter.printBase64Binary(outToken));
                    channel.sendResponse(wwwAuthenticateResponse);
                    throw new AuthException("Cannot authenticate");
                }

                //TODO FUTURE as privileged action?
                final User authenticatedUser = backend.authenticate(new AuthCredentials(((SimpleUserPrincipal) principal).getName(),
                        gssContext));
                authorizator.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), gssContext));

                decodedNegotiateHeader = null;
                authorizationHeader = null;

                log.debug("User '{}' is authenticated", authenticatedUser);

                return authenticatedUser;
            }

        } else {
            log.trace("No 'Authorization' header, send 401 and 'WWW-Authenticate Negotiate'");

            final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
            wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Negotiate");
            channel.sendResponse(wwwAuthenticateResponse);
            return null;

        }
    }

    /**
     * This class gets a gss credential via a privileged action.
     */
    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
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

    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static class AuthenticateAction implements PrivilegedAction<Principal> {

        private final HTTPSpnegoAuthenticator authenticator;
        private final GSSContext gssContext;
        private final boolean strip;

        public AuthenticateAction(final HTTPSpnegoAuthenticator authenticator, final GSSContext gssContext, final boolean strip) {
            this.authenticator = authenticator;
            this.gssContext = gssContext;
            this.strip = strip;
        }

        @Override
        public Principal run() {
            return new SimpleUserPrincipal(authenticator.getUsernameFromGSSContext(gssContext, strip));
        }
    }

    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private String getUsernameFromGSSContext(final GSSContext gssContext, final boolean strip) {
        if (gssContext.isEstablished()) {
            GSSName gssName = null;
            try {
                gssName = gssContext.getSrcName();
            } catch (final GSSException e) {
                log.warn("realmBase.gssNameFail", e);
            }

            if (gssName != null) {
                String name = gssName.toString();

                if (strip && name != null) {
                    final int i = name.indexOf('@');
                    if (i > 0) {
                        // Zero so we don;t leave a zero length name
                        name = name.substring(0, i);
                    }
                }

                return name;

            }
        }

        return null;
    }

    private static class SimpleUserPrincipal implements Principal, Serializable {

        private static final long serialVersionUID = -1;

        private final String username;

        public SimpleUserPrincipal(final String username) {
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
