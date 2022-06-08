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

package org.opensearch.security.auditlog.helper;

import java.util.Collections;

import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;

public class MockRestRequest extends RestRequest {

    public MockRestRequest() {
        //NamedXContentRegistry xContentRegistry, Map<String, String> params, String path,
        //Map<String, List<String>> headers, HttpRequest httpRequest, HttpChannel httpChannel
        super(NamedXContentRegistry.EMPTY, Collections.emptyMap(), "", Collections.emptyMap(), null, null);
    }

    @Override
    public Method method() {
        return Method.GET;
    }

    @Override
    public String uri() {
        return "";
    }

    @Override
    public boolean hasContent() {
        return false;
    }

    @Override
    public BytesReference content() {
        return null;
    }
}
