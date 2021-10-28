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

package com.amazon.dlic.auth.ldap2;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.opensearch.SpecialPermission;
import org.ldaptive.AddRequest;
import org.ldaptive.BindRequest;
import org.ldaptive.CompareRequest;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.DeleteRequest;
import org.ldaptive.LdapException;
import org.ldaptive.ModifyDnRequest;
import org.ldaptive.ModifyRequest;
import org.ldaptive.Response;
import org.ldaptive.SearchRequest;
import org.ldaptive.control.RequestControl;
import org.ldaptive.extended.ExtendedRequest;
import org.ldaptive.extended.UnsolicitedNotificationListener;
import org.ldaptive.provider.Provider;
import org.ldaptive.provider.ProviderConnection;
import org.ldaptive.provider.ProviderConnectionFactory;
import org.ldaptive.provider.SearchIterator;
import org.ldaptive.provider.SearchListener;
import org.ldaptive.provider.jndi.JndiProviderConfig;

public class PrivilegedProvider implements Provider<JndiProviderConfig> {

    private final Provider<JndiProviderConfig> delegate;

    public PrivilegedProvider(Provider<JndiProviderConfig> delegate) {
        this.delegate = delegate;
    }

    @Override
    public JndiProviderConfig getProviderConfig() {
        return this.delegate.getProviderConfig();
    }

    @Override
    public void setProviderConfig(JndiProviderConfig pc) {
        this.delegate.setProviderConfig(pc);
    }

    @Override
    public ProviderConnectionFactory<JndiProviderConfig> getConnectionFactory(ConnectionConfig cc) {
        ProviderConnectionFactory<JndiProviderConfig> connectionFactory = delegate.getConnectionFactory(cc);

        return new PrivilegedProviderConnectionFactory(connectionFactory);
    }

    @Override
    public Provider<JndiProviderConfig> newInstance() {
        return new PrivilegedProvider(this.delegate.newInstance());
    }

    private static class PrivilegedProviderConnectionFactory implements ProviderConnectionFactory<JndiProviderConfig> {

        private final ProviderConnectionFactory<JndiProviderConfig> delegate;

        PrivilegedProviderConnectionFactory(ProviderConnectionFactory<JndiProviderConfig> delegate) {
            this.delegate = delegate;
        }

        @Override
        public JndiProviderConfig getProviderConfig() {
            return this.delegate.getProviderConfig();
        }

        @Override
        public ProviderConnection create() throws LdapException {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            try {
                return AccessController.doPrivileged(new PrivilegedExceptionAction<ProviderConnection>() {
                    @Override
                    public ProviderConnection run() throws Exception {
                        return new PrivilegedProviderConnection(delegate.create(), getProviderConfig());
                    }
                });
            } catch (PrivilegedActionException e) {
                if (e.getException() instanceof LdapException) {
                    throw (LdapException) e.getException();
                } else if (e.getException() instanceof RuntimeException) {
                    throw (RuntimeException) e.getException();
                } else {
                    throw new RuntimeException(e.getException());
                }
            }
        }

    }

    private static class PrivilegedProviderConnection implements ProviderConnection {
        private final ProviderConnection delegate;
        private final JndiProviderConfig jndiProviderConfig;

        public PrivilegedProviderConnection(ProviderConnection delegate, JndiProviderConfig jndiProviderConfig) {
            this.delegate = delegate;
            this.jndiProviderConfig = jndiProviderConfig;
        }

        public Response<Void> bind(BindRequest request) throws LdapException {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            try {
                return AccessController.doPrivileged(new PrivilegedExceptionAction<Response<Void>>() {
                    @Override
                    public Response<Void> run() throws Exception {
                        if (jndiProviderConfig.getClassLoader() != null) {
                            ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();

                            try {
                                Thread.currentThread().setContextClassLoader(jndiProviderConfig.getClassLoader());
                                return delegate.bind(request);
                            } finally {
                                Thread.currentThread().setContextClassLoader(originalClassLoader);
                            }
                        } else {
                            return delegate.bind(request);
                        }
                    }
                });
            } catch (PrivilegedActionException e) {
                if (e.getException() instanceof LdapException) {
                    throw (LdapException) e.getException();
                } else if (e.getException() instanceof RuntimeException) {
                    throw (RuntimeException) e.getException();
                } else {
                    throw new RuntimeException(e.getException());
                }
            }
        }

        public Response<Void> add(AddRequest request) throws LdapException {
            return delegate.add(request);
        }

        public Response<Boolean> compare(CompareRequest request) throws LdapException {
            return delegate.compare(request);
        }

        public Response<Void> delete(DeleteRequest request) throws LdapException {
            return delegate.delete(request);
        }

        public Response<Void> modify(ModifyRequest request) throws LdapException {
            return delegate.modify(request);
        }

        public Response<Void> modifyDn(ModifyDnRequest request) throws LdapException {
            return delegate.modifyDn(request);
        }

        public SearchIterator search(SearchRequest request) throws LdapException {
            return delegate.search(request);
        }

        public void searchAsync(SearchRequest request, SearchListener listener) throws LdapException {
            delegate.searchAsync(request, listener);
        }

        public void abandon(int messageId, RequestControl[] controls) throws LdapException {
            delegate.abandon(messageId, controls);
        }

        public Response<?> extendedOperation(ExtendedRequest request) throws LdapException {
            return delegate.extendedOperation(request);
        }

        public void addUnsolicitedNotificationListener(UnsolicitedNotificationListener listener) {
            delegate.addUnsolicitedNotificationListener(listener);
        }

        public void removeUnsolicitedNotificationListener(UnsolicitedNotificationListener listener) {
            delegate.removeUnsolicitedNotificationListener(listener);
        }

        public void close(RequestControl[] controls) throws LdapException {
            delegate.close(controls);
        }
    }
}
