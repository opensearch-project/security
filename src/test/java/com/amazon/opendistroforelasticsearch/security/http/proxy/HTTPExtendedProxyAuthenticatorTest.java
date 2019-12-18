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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package com.amazon.opendistroforelasticsearch.security.http.proxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.http.HttpRequest;
import org.elasticsearch.http.HttpResponse;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.junit.Before;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.http.proxy.HTTPExtendedProxyAuthenticator;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;

public class HTTPExtendedProxyAuthenticatorTest {

    private HTTPExtendedProxyAuthenticator authenticator;
    private ThreadContext context = new ThreadContext(Settings.EMPTY);
    private Map<String, List<String>> headers = new HashMap<>();
    private Settings settings;

    @Before
    public void setup() {
        context.putTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE, Boolean.TRUE);
        settings = Settings.builder()
                .put("user_header","user")
                .build();
        authenticator = new HTTPExtendedProxyAuthenticator(settings, null);
    }

    @Test
    public void testGetType() {
        assertEquals("extended-proxy", authenticator.getType());
    }

    @Test(expected = ElasticsearchSecurityException.class)
    public void testThrowsExceptionWhenMissingXFFDone() {
        authenticator = new HTTPExtendedProxyAuthenticator(Settings.EMPTY, null);
        authenticator.extractCredentials(new TestRestRequest(),  new ThreadContext(Settings.EMPTY));
    }

    @Test
    public void testReturnsNullWhenUserHeaderIsUnconfigured() {
        authenticator = new HTTPExtendedProxyAuthenticator(Settings.EMPTY, null);
        assertNull(authenticator.extractCredentials(new TestRestRequest(), context));
    }

    @Test
    public void testReturnsNullWhenUserHeaderIsMissing() {
        
        assertNull(authenticator.extractCredentials(new TestRestRequest(), context));
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
        
        settings = Settings.builder().put(settings).put("attr_header_prefix","proxy_").build();
        authenticator = new HTTPExtendedProxyAuthenticator(settings,null);
        AuthCredentials creds = authenticator.extractCredentials(new TestRestRequest(headers), context);
        assertNotNull(creds);
        assertEquals("aValidUser", creds.getUsername());
        assertEquals("123,456", creds.getAttributes().get("attr.proxy.uid"));
        assertEquals("someothervalue", creds.getAttributes().get("attr.proxy.other"));
        assertTrue(creds.isComplete());
    }

    static class TestRestRequest extends RestRequest {
        
        public TestRestRequest() {
            super(NamedXContentRegistry.EMPTY, new HashMap<>(), "", new HashMap<>(),new HttpRequestImpl(),new HttpChannelImpl());
        }
        public TestRestRequest(Map<String, List<String>> headers) {
            super(NamedXContentRegistry.EMPTY, new HashMap<>(), "", headers,  new HttpRequestImpl(),new HttpChannelImpl());
        }
        public TestRestRequest(NamedXContentRegistry xContentRegistry, Map<String, String> params, String path,
                Map<String, List<String>> headers) {
            super(xContentRegistry, params, path, headers, new HttpRequestImpl(),new HttpChannelImpl());
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