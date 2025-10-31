/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import java.io.IOException;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.resources.sharing.ShareWith;

/**
 * This class represents a request to share access to a resource.
 *
 */
public class ShareRequest extends ActionRequest implements DocRequest {

    @JsonProperty("resource_id")
    private final String resourceId;
    @JsonProperty("resource_type")
    private final String resourceType;
    private final String resourceIndex;
    @JsonProperty("share_with")
    private final ShareWith shareWith;
    @JsonProperty("add")
    private final ShareWith add;
    @JsonProperty("revoke")
    private final ShareWith revoke;

    private final RestRequest.Method method;

    /**
     * Private constructor to enforce usage of Builder
     */
    private ShareRequest(Builder builder) {
        this.resourceId = builder.resourceId;
        this.resourceType = builder.resourceType;
        this.resourceIndex = builder.resourceIndex;
        this.shareWith = builder.shareWith;
        this.add = builder.add;
        this.revoke = builder.revoke;
        this.method = builder.method;
    }

    public ShareRequest(StreamInput in) throws IOException {
        super(in);
        this.method = in.readEnum(RestRequest.Method.class);
        this.resourceId = in.readString();
        this.resourceIndex = in.readString();
        this.resourceType = in.readString();
        this.shareWith = in.readOptionalWriteable(ShareWith::new);
        this.add = in.readOptionalWriteable(ShareWith::new);
        this.revoke = in.readOptionalWriteable(ShareWith::new);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(method);
        out.writeString(resourceId);
        out.writeString(resourceIndex);
        out.writeString(resourceType);
        out.writeOptionalWriteable(shareWith);
        out.writeOptionalWriteable(add);
        out.writeOptionalWriteable(revoke);
    }

    @Override
    public ActionRequestValidationException validate() {
        var arv = new ActionRequestValidationException();
        if (Strings.isNullOrEmpty(resourceType) || Strings.isNullOrEmpty(resourceId)) {
            arv.addValidationError("resource_id and resource_type must be present");
            throw arv;
        }

        // no further check needed in case of GET
        if (method == RestRequest.Method.GET) {
            return null;
        }
        // either of shareWith or patch must be present in the request
        if (shareWith == null && method == RestRequest.Method.PUT) {
            arv.addValidationError("share_with is required");
            throw arv;
        }
        if (method == RestRequest.Method.PATCH && add == null && revoke == null) {
            arv.addValidationError("either add or revoke must be present");
            throw arv;
        }
        return null;
    }

    public ShareWith getShareWith() {
        return shareWith;
    }

    public ShareWith getAdd() {
        return add;
    }

    public ShareWith getRevoke() {
        return revoke;
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    @Override
    public String type() {
        return resourceType;
    }

    /**
     * Get the index that this request operates on
     *
     * @return the index
     */
    @Override
    public String index() {
        return resourceIndex;
    }

    /**
     * Get the id of the document for this request
     *
     * @return the id
     */
    @Override
    public String id() {
        return resourceId;
    }

    /**
     * Builder for ShareRequest
     */
    public static class Builder {
        String resourceId;
        String resourceIndex;
        String resourceType;
        ShareWith shareWith;
        ShareWith add;
        ShareWith revoke;
        RestRequest.Method method;

        public void resourceId(String resourceId) {
            this.resourceId = resourceId;
        }

        public void resourceIndex(String resourceIndex) {
            this.resourceIndex = resourceIndex;
        }

        public void resourceType(String resourceType) {
            this.resourceType = resourceType;
        }

        public void shareWith(ShareWith shareWith) {
            this.shareWith = shareWith;
        }

        public void add(ShareWith add) {
            this.add = add;
        }

        public void revoke(ShareWith revoke) {
            this.revoke = revoke;
        }

        public void method(RestRequest.Method method) {
            this.method = method;
        }

        public ShareRequest build() {
            return new ShareRequest(this);
        }

        public void parseContent(XContentParser xContentParser, ResourcePluginInfo resourcePluginInfo) throws IOException {
            try (XContentParser parser = xContentParser) {
                XContentParser.Token token; // START_OBJECT
                while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                    if (token == XContentParser.Token.FIELD_NAME) {
                        String name = parser.currentName();
                        parser.nextToken();
                        switch (name) {
                            case "resource_id":
                                this.resourceId(parser.text());
                                break;
                            case "resource_type":
                                this.resourceType(parser.text());
                                this.resourceIndex(resourcePluginInfo.indexByType(parser.text()));
                                break;
                            case "share_with":
                                this.shareWith(ShareWith.fromXContent(parser));
                                break;
                            case "add":
                                this.add(ShareWith.fromXContent(parser));
                                break;
                            case "revoke":
                                this.revoke(ShareWith.fromXContent(parser));
                                break;
                            default:
                                parser.skipChildren();
                        }
                    }
                }
            }
        }
    }

}
