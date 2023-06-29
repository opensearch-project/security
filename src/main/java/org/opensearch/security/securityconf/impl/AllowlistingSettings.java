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

package org.opensearch.security.securityconf.impl;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestStatus;

public class AllowlistingSettings {
    private boolean enabled;
    private Map<String, List<HttpRequestMethods>> requests;

    /**
     * Used to parse the yml files, do not remove.
     */
    public AllowlistingSettings() {
        enabled = false;
        requests = Collections.emptyMap();
    }

    public AllowlistingSettings(AllowlistingSettings allowlistingSettings) {
        this.enabled = allowlistingSettings.getEnabled();
        this.requests = allowlistingSettings.getRequests();
    }

    public boolean getEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Map<String, List<HttpRequestMethods>> getRequests() {
        return this.requests == null ? Collections.emptyMap(): this.requests;
    }

    public void setRequests(Map<String, List<HttpRequestMethods>> requests) {
        this.requests = requests;
    }

    @Override
    public String toString() {
        return "AllowlistingSetting [enabled=" + enabled + ", requests=" + requests + ']';
    }


    /**
     * Helper function to check if a rest request is allowlisted, by checking if the path is allowlisted,
     * and then if the Http method is allowlisted.
     * This method also contains logic to trim the path request, and check both with and without extra '/'
     * This allows users to allowlist either /_cluster/settings/ or /_cluster/settings, to avoid potential issues.
     * This also ensures that requests to the cluster can have a trailing '/'
     * Scenarios:
     * 1. Allowlisted API does not have an extra '/'. eg: If GET /_cluster/settings is allowlisted, these requests have the following response:
     *      GET /_cluster/settings  - OK
     *      GET /_cluster/settings/ - OK
     *
     * 2. Allowlisted API has an extra '/'. eg: If GET /_cluster/settings/ is allowlisted, these requests have the following response:
     *      GET /_cluster/settings  - OK
     *      GET /_cluster/settings/ - OK
     */
    private boolean requestIsAllowlisted(RestRequest request){

        //ALSO ALLOWS REQUEST TO HAVE TRAILING '/'
        //pathWithoutTrailingSlash stores the endpoint path without extra '/'. eg: /_cat/nodes
        //pathWithTrailingSlash stores the endpoint path with extra '/'. eg: /_cat/nodes/
        String path = request.path();
        String pathWithoutTrailingSlash;
        String pathWithTrailingSlash;

        //first obtain pathWithoutTrailingSlash, then add a '/' to it to get pathWithTrailingSlash
        pathWithoutTrailingSlash = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        pathWithTrailingSlash = pathWithoutTrailingSlash + '/';

        //check if pathWithoutTrailingSlash is allowlisted
        if(requests.containsKey(pathWithoutTrailingSlash) && requests.get(pathWithoutTrailingSlash).contains(HttpRequestMethods.valueOf(request.method().toString())))
            return true;

        //check if pathWithTrailingSlash is allowlisted
        if(requests.containsKey(pathWithTrailingSlash) && requests.get(pathWithTrailingSlash).contains(HttpRequestMethods.valueOf(request.method().toString())))
            return true;
        return false;
    }

    /**
     * Checks that a given request is allowlisted, for non SuperAdmin.
     * For SuperAdmin this function is bypassed.
     * In a future version, should add a regex check to improve the functionality.
     * Currently, each individual PUT/PATCH request needs to be allowlisted separately for the specific resource to be changed/added.
     * This should be improved so that, for example if PUT /_opendistro/_security/api/rolesmapping is allowlisted,
     * then all PUT /_opendistro/_security/api/rolesmapping/{resource_name} work.
     * Currently, each resource_name has to be allowlisted separately
     */
    public boolean checkRequestIsAllowed(RestRequest request, RestChannel channel,
                                          NodeClient client) throws IOException {
        // if allowlisting is enabled but the request is not allowlisted, then return false, otherwise true.
        if (this.enabled && !requestIsAllowlisted(request)){
            channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, channel.newErrorBuilder().startObject()
                    .field("error", request.method() + " " + request.path() + " API not allowlisted")
                    .field("status", RestStatus.FORBIDDEN)
                    .endObject()
            ));
            return false;
        }
        return true;
    }
}
