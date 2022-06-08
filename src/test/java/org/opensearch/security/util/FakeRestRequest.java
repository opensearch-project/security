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

package org.opensearch.security.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensearch.common.bytes.BytesReference;
import org.opensearch.rest.RestRequest;

public class FakeRestRequest extends RestRequest {

    //private final Map<String, String> headers;
    private final BytesReference content;
    private final Method method;


    public FakeRestRequest() {
        this(new HashMap<>(), new HashMap<>(), null, Method.GET, "/");
    }

    public FakeRestRequest(Map<String, String> headers, Map<String, String> params) {
        this(headers, params, null, Method.GET, "/");
    }

    private FakeRestRequest(Map<String, String> headers, Map<String, String> params, BytesReference content, Method method, String path) {
        //NamedXContentRegistry xContentRegistry, Map<String, String> params, String path,
        //Map<String, List<String>> headers, HttpRequest httpRequest, HttpChannel httpChannel
        super(null, params, path, convert(headers), null, null);
        //this.headers = headers;
        this.content = content;
        this.method = method;
    }

    @Override
    public Method method() {
        return method;
    }

    @Override
    public String uri() {
        return rawPath();
    }

    @Override
    public boolean hasContent() {
        return content != null;
    }

    @Override
    public BytesReference content() {
        return content;
    }

    public static class Builder {

        private Map<String, String> headers = new HashMap<>();

        private Map<String, String> params = new HashMap<>();

        private BytesReference content;

        private String path = "/";

        private Method method = Method.GET;

        public Builder withHeaders(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }

        public Builder withParams(Map<String, String> params) {
            this.params = params;
            return this;
        }

        public Builder withContent(BytesReference content) {
            this.content = content;
            return this;
        }

        public Builder withPath(String path) {
            this.path = path;
            return this;
        }

        public Builder withMethod(Method method) {
            this.method = method;
            return this;
        }

        public FakeRestRequest build() {
            return new FakeRestRequest(headers, params, content, method, path);
        }

    }

    private static Map<String, List<String>> convert(Map<String, String> headers) {
        Map<String, List<String>> ret = new HashMap<String, List<String>>();
        for (String h:headers.keySet()) {
            ret.put(h, Collections.singletonList(headers.get(h)));
        }
        return ret;
    }

}
