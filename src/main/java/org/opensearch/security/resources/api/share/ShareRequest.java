/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.spi.resources.sharing.ShareWith;

import joptsimple.internal.Strings;

/**
 * This class represents a request to share access to a resource.
 *
 */
public class ShareRequest extends ActionRequest implements DocRequest {

    @JsonProperty("resource_id")
    private final String resourceId;
    @JsonProperty("resource_index")
    private final String resourceIndex;
    @JsonProperty("share_with")
    private final ShareWith shareWith;
    @JsonProperty("patch")
    private final Map<String, ShareWith> patch;

    private final RestRequest.Method method;

    /**
     * Private constructor to enforce usage of Builder
     */
    private ShareRequest(Builder builder) {
        this.resourceId = builder.resourceId;
        this.resourceIndex = builder.resourceIndex;
        this.shareWith = builder.shareWith;
        this.patch = builder.patch;
        this.method = builder.method;
    }

    public ShareRequest(StreamInput in) throws IOException {
        super(in);
        this.resourceId = in.readString();
        this.resourceIndex = in.readString();
        this.shareWith = in.readOptionalWriteable(ShareWith::new);
        this.patch = in.readMap(StreamInput::readString, ShareWith::new);
        this.method = in.readEnum(RestRequest.Method.class);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(resourceId);
        out.writeString(resourceIndex);
        if (shareWith != null) {
            shareWith.writeTo(out);
        }
        if (patch != null) {
            out.writeString(patch.toString());
        }
        out.writeEnum(method);
    }

    @Override
    public ActionRequestValidationException validate() {
        var arv = new ActionRequestValidationException();
        if (Strings.isNullOrEmpty(resourceIndex) || Strings.isNullOrEmpty(resourceId)) {
            arv.addValidationError("resource_id and resource_index must be present");
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
        if (method == RestRequest.Method.PATCH) {
            if (patch == null || patch.isEmpty()) {
                arv.addValidationError("patch is required");
            } else if (!patch.containsKey("add") && !patch.containsKey("revoke")) {
                arv.addValidationError("patch must not be empty");
            }
            throw arv;
        }
        return null;
    }

    public ShareWith getShareWith() {
        return shareWith;
    }

    public Map<String, ShareWith> getPatch() {
        return patch;
    }

    public RestRequest.Method getMethod() {
        return method;
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
        private String resourceId;
        private String resourceIndex;
        private ShareWith shareWith;
        private Map<String, ShareWith> patch;
        private RestRequest.Method method;

        public void resourceId(String resourceId) {
            this.resourceId = resourceId;
        }

        public void resourceIndex(String resourceIndex) {
            this.resourceIndex = resourceIndex;
        }

        public void shareWith(ShareWith shareWith) {
            this.shareWith = shareWith;
        }

        public void patch(Map<String, ShareWith> patch) {
            this.patch = patch;
        }

        public void method(RestRequest.Method method) {
            this.method = method;
        }

        public ShareRequest build() {
            return new ShareRequest(this);
        }

        /**
         * Parses a patch object from JSON, extracting "share_with" and "revoke" sub-objects.
         */
        public void parsePatch(XContentParser parser) throws IOException {
            Map<String, ShareWith> map = new HashMap<>(2);
            XContentParser.Token tok = parser.currentToken();
            if (tok != XContentParser.Token.START_OBJECT) {
                throw new IllegalArgumentException("Expected patch object");
            }
            while ((tok = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                if (tok == XContentParser.Token.FIELD_NAME) {
                    String field = parser.currentName();
                    parser.nextToken();
                    if ("add".equals(field) || "revoke".equals(field)) {
                        map.put(field, ShareWith.fromXContent(parser));
                    } else {
                        parser.skipChildren();
                    }
                }
            }
            this.patch = map;
        }

        public void parseContent(XContentParser xContentParser) throws IOException {
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
                            case "resource_index":
                                this.resourceIndex(parser.text());
                                break;
                            case "share_with":
                                this.shareWith(ShareWith.fromXContent(parser));
                                break;
                            case "patch":
                                this.parsePatch(parser);
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
