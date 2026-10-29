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
package org.opensearch.security.http;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

public class HTTPProxyAuthenticatorTest {

    private HTTPProxyAuthenticator authenticator;
    private final ThreadContext context = new ThreadContext(Settings.EMPTY);
    private final Map<String, List<String>> headers = new HashMap<>();
    private Settings settings;

    @Before
    public void setup() {
        context.putTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE, Boolean.TRUE);
        settings = Settings.builder().put("user_header", "user").build();
        authenticator = new HTTPProxyAuthenticator(settings, null);
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testThrowsExceptionWhenMissingXFFDone() {
        authenticator.extractCredentials(new TestRestRequest().asSecurityRequest(), new ThreadContext(Settings.EMPTY));
    }

    @Test
    public void testReturnsNullWhenUserHeaderIsMissing() {
        assertNull(authenticator.extractCredentials(new TestRestRequest().asSecurityRequest(), context));
    }

    @Test
    public void testReturnsCredentialsForNormalUser() {
        headers.put("user", new ArrayList<>());
        headers.get("user").add("aValidUser");
        AuthCredentials creds = authenticator.extractCredentials(new TestRestRequest(headers).asSecurityRequest(), context);
        assertNotNull(creds);
        assertThat(creds.getUsername(), is("aValidUser"));
    }

    /**
     * A caller-supplied proxy user header must not be able to assert an internal plugin identity.
     * The subject {@code plugin:org.opensearch.ml.plugin.MachineLearningPlugin} is the exact value
     * used by the HackerOne RCE chain (H1-3951245) to impersonate the ML plugin.
     */
    @Test
    public void testRejectsReservedPluginPrefix() {
        headers.put("user", new ArrayList<>());
        headers.get("user").add("plugin:org.opensearch.ml.plugin.MachineLearningPlugin");
        assertRejected(
            authenticator.extractCredentials(new TestRestRequest(headers).asSecurityRequest(), context),
            "plugin:org.opensearch.ml.plugin.MachineLearningPlugin"
        );
    }

    /** The API-token reserved prefix must likewise be rejected from an external proxy header. */
    @Test
    public void testRejectsReservedTokenPrefix() {
        headers.put("user", new ArrayList<>());
        headers.get("user").add("token:some-api-token");
        assertRejected(authenticator.extractCredentials(new TestRestRequest(headers).asSecurityRequest(), context), "token:some-api-token");
    }

    /** A legitimate username that merely contains the substring must still be accepted. */
    @Test
    public void testAcceptsNonPrefixSubstring() {
        headers.put("user", new ArrayList<>());
        headers.get("user").add("not-a-plugin:user");
        AuthCredentials creds = authenticator.extractCredentials(new TestRestRequest(headers).asSecurityRequest(), context);
        assertNotNull(creds);
        assertThat(creds.getUsername(), is("not-a-plugin:user"));
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
            return null;
        }

        @Override
        public String uri() {
            return null;
        }

        @Override
        public BytesReference content() {
            return null;
        }

        @Override
        public Map<String, List<String>> getHeaders() {
            return null;
        }

        @Override
        public List<String> strictCookies() {
            return null;
        }

        @Override
        public HttpVersion protocolVersion() {
            return null;
        }

        @Override
        public HttpRequest removeHeader(String header) {
            return null;
        }

        @Override
        public HttpResponse createResponse(RestStatus status, BytesReference content) {
            return null;
        }

        @Override
        public void release() {}

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
        public void close() {}

        @Override
        public void addCloseListener(ActionListener<Void> listener) {}

        @Override
        public boolean isOpen() {
            return false;
        }

        @Override
        public void sendResponse(HttpResponse response, ActionListener<Void> listener) {}

        @Override
        public InetSocketAddress getLocalAddress() {
            return null;
        }

        @Override
        public InetSocketAddress getRemoteAddress() {
            return null;
        }
    }
}
