/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.bwc.helper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.client.WarningsHandler;

import static org.apache.http.entity.ContentType.APPLICATION_JSON;

public class RestHelper {

    private static final Logger log = LogManager.getLogger(RestHelper.class);

    public static HttpEntity toHttpEntity(String jsonString) {
        return new StringEntity(jsonString, APPLICATION_JSON);
    }

    public static Response get(RestClient client, String url) throws IOException {
        return makeRequest(client, "GET", url, null, null);
    }

    public static Response makeRequest(RestClient client, String method, String endpoint, HttpEntity entity) throws IOException {
        return makeRequest(client, method, endpoint, entity, null);
    }

    public static Response makeRequest(RestClient client, String method, String endpoint, HttpEntity entity, List<Header> headers)
        throws IOException {
        log.info("Making request " + method + " " + endpoint + ", with headers " + headers);

        Request request = new Request(method, endpoint);

        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.setWarningsHandler(WarningsHandler.PERMISSIVE);
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

    public static List<Response> requestAgainstAllNodes(RestClient client, String method, String endpoint, HttpEntity entity)
        throws IOException {
        return requestAgainstAllNodes(client, method, endpoint, entity, null);
    }

    public static List<Response> requestAgainstAllNodes(
        RestClient client,
        String method,
        String endpoint,
        HttpEntity entity,
        List<Header> headers
    ) throws IOException {
        int nodeCount = client.getNodes().size();
        List<Response> responses = new ArrayList<>();
        while (nodeCount-- > 0) {
            responses.add(makeRequest(client, method, endpoint, entity, headers));
        }
        return responses;
    }

    public static Header getAuthorizationHeader(String username, String password) {
        return new BasicHeader("Authorization", "Basic " + username + ":" + password);
    }
}
