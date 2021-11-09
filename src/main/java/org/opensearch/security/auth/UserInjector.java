/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.auth;

import java.io.ObjectStreamException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityUtils;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import com.google.common.base.Strings;

public class UserInjector {

    protected final Logger log = LogManager.getLogger(UserInjector.class);

    private final ThreadPool threadPool;
    private final AuditLog auditLog;
    private final XFFResolver xffResolver;
    private final Boolean injectUserEnabled;

    UserInjector(Settings settings, ThreadPool threadPool, AuditLog auditLog, XFFResolver xffResolver) {
        this.threadPool = threadPool;
        this.auditLog = auditLog;
        this.xffResolver = xffResolver;
        this.injectUserEnabled = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false);

    }

    static class InjectedUser extends User {
        private transient TransportAddress transportAddress;

        public InjectedUser(String name) {
            super(name);
        }

        private Object writeReplace() throws ObjectStreamException {
            User user = new User(getName());
            user.addRoles(getRoles());
            user.addSecurityRoles(getSecurityRoles());
            user.setRequestedTenant(getRequestedTenant());
            user.addAttributes(getCustomAttributesMap());
            user.setInjected(true);
            return user;
        }

        public TransportAddress getTransportAddress() {
            return transportAddress;
        }

        public void setTransportAddress(String addr) throws UnknownHostException, IllegalArgumentException {
            // format is ip:port
            String[] ipAndPort = addr.split(":");
            if (ipAndPort.length != 2) {
                throw new IllegalArgumentException("Remote address must have format ip:port");
            }

            InetAddress iAdress = InetAddress.getByName(ipAndPort[0]);
            int port = Integer.parseInt(ipAndPort[1]);

            this.transportAddress = new TransportAddress(iAdress, port);
        }
    }

    InjectedUser getInjectedUser() {
        if (!injectUserEnabled) {
            return null;
        }

        String injectedUserString = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER);

        if (log.isDebugEnabled()) {
            log.debug("Injected user string: {}", injectedUserString);
        }

        if (Strings.isNullOrEmpty(injectedUserString)) {
            return null;
        }
        // username|role1,role2|remoteIP:port|attributeKey,attributeValue,attributeKey,attributeValue, ...|requestedTenant
        String[] parts = injectedUserString.split("\\|");

        if (parts.length == 0) {
            log.error("User string malformed, could not extract parts. User string was '{}.' User injection failed.", injectedUserString);
            return null;
        }

        // username
        if (Strings.isNullOrEmpty(parts[0])) {
            log.error("Username must not be null, user string was '{}.' User injection failed.", injectedUserString);
            return null;
        }

        final InjectedUser injectedUser = new InjectedUser(parts[0]);

        // backend roles
        if (parts.length > 1 && !Strings.isNullOrEmpty(parts[1])) {
            if (parts[1].length() > 0) {
                injectedUser.addRoles(Arrays.asList(parts[1].split(",")));
            }
        }

        // custom attributes
        if (parts.length > 3 && !Strings.isNullOrEmpty(parts[3])) {
            Map<String, String> attributes = SecurityUtils.mapFromArray((parts[3].split(",")));
            if (attributes == null) {
                log.error("Could not parse custom attributes {}, user injection failed.", parts[3]);
                return null;
            } else {
                injectedUser.addAttributes(attributes);
            }
        }

        // requested tenant
        if (parts.length > 4 && !Strings.isNullOrEmpty(parts[4])) {
            injectedUser.setRequestedTenant(parts[4]);
        }

        // remote IP - we can set it only once, so we do it last. If non is given,
        // BackendRegistry/XFFResolver will do the job
        if (parts.length > 2 && !Strings.isNullOrEmpty(parts[2])) {
            try {
                injectedUser.setTransportAddress(parts[2]);
            } catch (UnknownHostException | IllegalArgumentException e) {
                log.error("Cannot parse remote IP or port: {}, user injection failed.", parts[2], e);
                return null;
            }
        }

        // mark user injected for proper admin handling
        injectedUser.setInjected(true);

        if (log.isTraceEnabled()) {
            log.trace("Injected user object:{} ", injectedUser.toString());
        }

        return injectedUser;
    }


    boolean injectUser(RestRequest request) {
        InjectedUser injectedUser = getInjectedUser();
        if(injectedUser == null) {
            return false;
        }

        // Set remote address into the thread context
        if (injectedUser.getTransportAddress() != null) {
            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, injectedUser.getTransportAddress());
        } else {
            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, xffResolver.resolve(request));
        }

        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, injectedUser);
        auditLog.logSucceededLogin(injectedUser.getName(), true, null, request);

        return true;
    }
}
