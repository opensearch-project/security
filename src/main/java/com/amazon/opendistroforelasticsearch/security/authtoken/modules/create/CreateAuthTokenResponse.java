package com.amazon.opendistroforelasticsearch.security.authtoken.modules.create;

import java.io.IOException;

import com.amazon.opendistroforelasticsearch.security.authtoken.AuthToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;

public class CreateAuthTokenResponse extends ActionResponse implements ToXContentObject {
    private static final Logger log = LogManager.getLogger(CreateAuthTokenResponse.class);
    private AuthToken authToken;
    private String jwt;

    public CreateAuthTokenResponse() {
    }

    public CreateAuthTokenResponse(AuthToken authToken, String jwt) {
        this.authToken = authToken;
        this.jwt = jwt;
    }

    public CreateAuthTokenResponse(StreamInput in) throws IOException {
        super(in);
        this.authToken = new AuthToken(in);
        this.jwt = in.readString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        this.authToken.writeTo(out);
        out.writeString(jwt);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("token", jwt);
        builder.field("id", authToken.getId());
        authToken.toXContentFragment(builder, params);
        builder.endObject();
        return builder;
    }

    public AuthToken getAuthToken() {
        return authToken;
    }

    public String getJwt() {
        return jwt;
    }

}
