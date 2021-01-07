package com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule;

import java.io.IOException;

import com.amazon.dlic.auth.http.jwt.authtoken.api.AuthToken;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.StatusToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.RestStatus;

public class GetAuthTokenResponse extends ActionResponse implements StatusToXContentObject {

    private AuthToken authToken;
    private RestStatus restStatus;
    private String error;

    public GetAuthTokenResponse() {
    }

    public GetAuthTokenResponse(AuthToken authToken) {
        this.authToken = authToken;
        this.restStatus = RestStatus.OK;
    }

    public GetAuthTokenResponse(RestStatus restStatus, String error) {
        this.restStatus = restStatus;
        this.error = error;
    }

    public GetAuthTokenResponse(StreamInput in) throws IOException {
        super(in);
        this.restStatus = in.readEnum(RestStatus.class);
        this.error = in.readOptionalString();

        if (in.readBoolean()) {
            this.authToken = new AuthToken(in);
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(this.restStatus);
        out.writeOptionalString(this.error);
        out.writeBoolean(this.authToken != null);

        if (this.authToken != null) {
            this.authToken.writeTo(out);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        if (authToken != null) {
            authToken.toXContent(builder, params);
        } else {
            builder.startObject();

            if (restStatus != null) {
                builder.field("status", restStatus.getStatus());
            }

            if (error != null) {
                builder.field("error", error);
            }

            builder.endObject();
        }

        return builder;
    }

    public AuthToken getAuthToken() {
        return authToken;
    }

    @Override
    public RestStatus status() {
        return restStatus;
    }

}

