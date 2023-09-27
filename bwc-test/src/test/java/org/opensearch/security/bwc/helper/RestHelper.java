/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.bwc.helper;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.util.Strings;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.client.WarningsHandler;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;


import static org.apache.hc.core5.http.ContentType.APPLICATION_JSON;

public class RestHelper {

    private static final Logger log = LogManager.getLogger(RestHelper.class);

    public static HttpEntity toHttpEntity(String jsonString) {
        return new StringEntity(jsonString, APPLICATION_JSON);
    }

    public static Response get(RestClient client, String url) throws IOException {
        return makeRequest(client, "GET", url, null, null);
    }

    public static Response makeRequest(
            RestClient client,
            String method,
            String endpoint,
            HttpEntity entity
    ) throws IOException {
        return makeRequest(client, method, endpoint, entity, null);
    }

    public static Response makeRequest(
        RestClient client,
        String method,
        String endpoint,
        HttpEntity entity,
        List<Header> headers
    ) throws IOException {
        log.info("Making request " + method + " " + endpoint + ", with headers " + headers);

        Request request = new Request(method, endpoint);

        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        if (headers != null) {
            headers.forEach(header -> options.addHeader(header.getName(), header.getValue()));
        }
        request.setOptions(options.build());

        if (entity != null) {
            request.setEntity(entity);
        }

        Response response = client.performRequest(request);
        log.info("Recieved response " + response.getStatusLine());
        return response;
    }

    public static Header getAuthorizationHeader(String username, String password) {
        return new BasicHeader("Authorization", "Basic " +username + ":" + password);
    }
}
