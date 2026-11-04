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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.security.http.proxy;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.http.HttpChannel;
import org.opensearch.http.HttpRequest;
import org.opensearch.http.HttpResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auth.AuthenticationFailureReason;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.AuthCredentials;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class HTTPExtendedProxyAuthenticatorTest {

    private HTTPExtendedProxyAuthenticator authenticator;
    private ThreadContext context = new ThreadContext(Settings.EMPTY);
    private Map<String, List<String>> headers = new HashMap<>();
    private Settings settings;

    @Before
    public void setup() {
        context.putTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE, Boolean.TRUE);
        settings = Settings.builder().put("user_header", "user").build();
        authenticator = new HTTPExtendedProxyAuthenticator(settings, null);
    }

    @Test
    public void testGetType() {
        assertThat(authenticator.getType(), is("extended-proxy"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testThrowsExceptionWhenMissingXFFDone() {
        authenticator = new HTTPExtendedProxyAuthenticator(Settings.EMPTY, null);
        authenticator.extractCredentials(new TestRestRequest().asSecurityRequest(), new ThreadContext(Settings.EMPTY));
    }

    @Test
    public void testReturnsNullWhenUserHeaderIsUnconfigured() {
        authenticator = new HTTPExtendedProxyAuthenticator(Settings.EMPTY, null);
        assertNull(authenticator.extractCredentials(new TestRestRequest().asSecurityRequest(), context));
    }

    @Test
    public void testReturnsNullWhenUserHeaderIsMissing() {

        assertNull(authenticator.extractCredentials(new TestRestRequest().asSecurityRequest(), context));
    }

    @Test

    public void testReturnsCredentials() {
        headers.put("user", new ArrayList<>());
        headers.put("proxy_uid", new ArrayList<>());
        headers.put("proxy_other", new ArrayList<>());
        headers.get("user").add("aValidUser");
        headers.get("proxy_uid").add("123");
        headers.get("proxy_uid").add("456");
        headers.get("proxy_other").add("someothervalue");

        settings = Settings.builder().put(settings).put("attr_header_prefix", "proxy_").build();
        authenticator = new HTTPExtendedProxyAuthenticator(settings, null);
        AuthCredentials creds = authenticator.extractCredentials(new TestRestRequest(headers).asSecurityRequest(), context);
        assertNotNull(creds);
        assertThat(creds.getUsername(), is("aValidUser"));
        assertThat(creds.getAttributes().get("attr.proxy.uid"), is("123,456"));
        assertThat(creds.getAttributes().get("attr.proxy.other"), is("someothervalue"));
        assertTrue(creds.isComplete());
    }

    @Test
    public void testTrimOnRoles() {
        headers.put("user", new ArrayList<>());
        headers.put("roles", new ArrayList<>());
        headers.get("user").add("aValidUser");
        headers.get("roles").add("role1, role2,\t");

        settings = Settings.builder().put(settings).put("roles_header", "roles").put("roles_separator", ",").build();
        authenticator = new HTTPExtendedProxyAuthenticator(settings, null);
        AuthCredentials creds = authenticator.extractCredentials(new TestRestRequest(headers).asSecurityRequest(), context);
        assertNotNull(creds);
        assertThat(creds.getUsername(), is("aValidUser"));
        assertThat(creds.getBackendRoles(), is(ImmutableSet.of("role1", "role2")));
        assertTrue(creds.isComplete());
    }

    /**
     * A reserved internal identity prefix supplied via the proxy user header must be rejected
     * (inherited from the base HTTPProxyAuthenticator guard) before any attribute extraction.
     * {@code plugin:org.opensearch.ml.plugin.MachineLearningPlugin} is the exact value used by the
     * HackerOne RCE chain (H1-3951245) to impersonate the ML plugin.
     */
    @Test
    public void testRejectsReservedPluginPrefix() {
        headers.put("user", new ArrayList<>());
        // Configure attribute extraction so the test also proves it is skipped for a rejected header
        authenticator = new HTTPExtendedProxyAuthenticator(
            Settings.builder().put(settings).put("attr_header_prefix", "proxy_").build(),
            null
        );
        headers.put("proxy_uid", new ArrayList<>(List.of("123")));
        headers.get("user").add("plugin:org.opensearch.ml.plugin.MachineLearningPlugin");
        assertRejected(
            authenticator.extractCredentials(new TestRestRequest(headers).asSecurityRequest(), context),
            "plugin:org.opensearch.ml.plugin.MachineLearningPlugin"
        );
    }

    @Test
    public void testRejectsReservedTokenPrefix() {
        headers.put("user", new ArrayList<>());
        // Configure attribute extraction so the test also proves it is skipped for a rejected header
        authenticator = new HTTPExtendedProxyAuthenticator(
            Settings.builder().put(settings).put("attr_header_prefix", "proxy_").build(),
            null
        );
        headers.put("proxy_uid", new ArrayList<>(List.of("123")));
        headers.get("user").add("token:some-api-token");
        assertRejected(authenticator.extractCredentials(new TestRestRequest(headers).asSecurityRequest(), context), "token:some-api-token");
    }

    /** The credential must be refused, never complete, and carry the attempted subject for the FAILED_LOGIN audit event. */
    private static void assertRejected(final AuthCredentials credentials, final String subject) {
        assertNotNull(credentials);
        assertTrue(credentials.isRejected());
        assertFalse(credentials.isComplete());
        assertThat(credentials.getAttemptedPrincipal(), is(subject));
        assertThat(credentials.getFailureReason(), is(AuthenticationFailureReason.RESERVED_SUBJECT_PREFIX));
        assertTrue(credentials.getAttributes().isEmpty());
    }

    static class TestRestRequest extends RestRequest {

        public TestRestRequest() {
            super(NamedXContentRegistry.EMPTY, new HashMap<>(), "", new HashMap<>(), new HttpRequestImpl(), new HttpChannelImpl());
        }

        public TestRestRequest(Map<String, List<String>> headers) {
            super(NamedXContentRegistry.EMPTY, new HashMap<>(), "", headers, new HttpRequestImpl(), new HttpChannelImpl());
        }

        public TestRestRequest(
            NamedXContentRegistry xContentRegistry,
            Map<String, String> params,
            String path,
            Map<String, List<String>> headers
        ) {
            super(xContentRegistry, params, path, headers, new HttpRequestImpl(), new HttpChannelImpl());
        }

        @Override
        public Method method() {
            return null;
        }

        @Override
        public String uri() {
            return null;
        }

        @Override
        public boolean hasContent() {
            return false;
        }

        public SecurityRequestChannel asSecurityRequest() {
            return SecurityRequestFactory.from(this, null);
        }
    }

    static class HttpRequestImpl implements HttpRequest {

        @Override
        public Method method() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public String uri() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public BytesReference content() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Map<String, List<String>> getHeaders() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public List<String> strictCookies() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public HttpVersion protocolVersion() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public HttpRequest removeHeader(String header) {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public HttpResponse createResponse(RestStatus status, BytesReference content) {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void release() {

        }

        @Override
        public HttpRequest releaseAndCopy() {
            return null;
        }

        @Override
        public Exception getInboundException() {
            return null;
        }
    }

    static class HttpChannelImpl implements HttpChannel {

        @Override
        public void close() {
            // TODO Auto-generated method stub

        }

        @Override
        public void addCloseListener(ActionListener<Void> listener) {
            // TODO Auto-generated method stub

        }

        @Override
        public boolean isOpen() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public void sendResponse(HttpResponse response, ActionListener<Void> listener) {
            // TODO Auto-generated method stub

        }

        @Override
        public InetSocketAddress getLocalAddress() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public InetSocketAddress getRemoteAddress() {
            // TODO Auto-generated method stub
            return null;
        }

    }
}
