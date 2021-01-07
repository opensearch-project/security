package com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule;

import java.io.IOException;

import com.amazon.dlic.auth.http.jwt.authtoken.api.AuthToken;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.support.nodes.BaseNodesRequest;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;


public class PushAuthTokenUpdateRequest extends BaseNodesRequest<PushAuthTokenUpdateRequest> {

    private AuthToken updatedToken;
    private UpdateType updateType;
    private long newHash;

    public PushAuthTokenUpdateRequest(StreamInput in) throws IOException {
        super(in);
        this.updatedToken = new AuthToken(in);
        this.updateType = in.readEnum(UpdateType.class);
        this.newHash = in.readLong();
    }

    public PushAuthTokenUpdateRequest(AuthToken updatedToken, UpdateType updateType, long newHash) {
        super(new String[0]);
        this.updatedToken = updatedToken;
        this.updateType = updateType;
        this.newHash = newHash;
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        updatedToken.writeTo(out);
        out.writeEnum(updateType);
        out.writeLong(newHash);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public static enum UpdateType {
        NEW, REVOKED
    }

    public AuthToken getUpdatedToken() {
        return updatedToken;
    }

    public UpdateType getUpdateType() {
        return updateType;
    }

    @Override
    public String toString() {
        return "PushAuthTokenUpdateRequest [updatedToken=" + updatedToken + ", updateType=" + updateType + "]";
    }

    public long getNewHash() {
        return newHash;
    }
}

