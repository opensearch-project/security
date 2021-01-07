package com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule;

import java.io.IOException;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;


public class RevokeAuthTokenRequest extends ActionRequest {

    private String authTokenId;

    public RevokeAuthTokenRequest() {
        super();
    }

    public RevokeAuthTokenRequest(String authTokenId) {
        super();
        this.authTokenId = authTokenId;

    }

    public RevokeAuthTokenRequest(StreamInput in) throws IOException {
        super(in);
        this.authTokenId = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(authTokenId);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getAuthTokenId() {
        return authTokenId;
    }

}

