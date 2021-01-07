package com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule;

import java.io.IOException;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.StatusToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.RestStatus;

public class RevokeAuthTokenResponse extends ActionResponse implements StatusToXContentObject {

    private String info;
    private RestStatus restStatus;
    private String error;

    public RevokeAuthTokenResponse(String status) {
        this.info = status;
        this.restStatus = RestStatus.OK;
    }

    public RevokeAuthTokenResponse(RestStatus restStatus, String error) {
        this.restStatus = restStatus;
        this.error = error;
    }

    public RevokeAuthTokenResponse(StreamInput in) throws IOException {
        super(in);
        this.info = in.readOptionalString();
        this.restStatus = in.readEnum(RestStatus.class);
        this.error = in.readOptionalString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(info);
        out.writeEnum(this.restStatus);
        out.writeOptionalString(this.error);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();

        if (restStatus != null) {
            builder.field("status", restStatus.getStatus());
        }

        if (info != null) {
            builder.field("info", info);
        }

        if (error != null) {
            builder.field("error", error);
        }

        builder.endObject();
        return builder;
    }

    @Override
    public RestStatus status() {
        return restStatus;
    }

}

