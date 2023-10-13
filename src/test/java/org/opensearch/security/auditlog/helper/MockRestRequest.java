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

package org.opensearch.security.auditlog.helper;

import java.util.Collections;

import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.filter.SecurityRequestFactory;

public class MockRestRequest extends RestRequest {

    public MockRestRequest() {
        // NamedXContentRegistry xContentRegistry, Map<String, String> params, String path,
        // Map<String, List<String>> headers, HttpRequest httpRequest, HttpChannel httpChannel
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

    public SecurityRequestChannel asSecurityRequest() {
        return SecurityRequestFactory.from(this, null);
    }
}
