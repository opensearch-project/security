package com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule;

import java.io.IOException;
import java.time.Duration;
import java.time.temporal.TemporalAmount;

import com.amazon.dlic.auth.http.jwt.authtoken.api.RequestedPrivileges;
import com.amazon.dlic.auth.http.jwt.authtoken.api.temporal.TemporalAmountFormat;
import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.*;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentType;


public class CreateAuthTokenRequest extends ActionRequest implements ToXContentObject {

    private String tokenName;
    private String audience;
    private TemporalAmount expiresAfter;
    private RequestedPrivileges requestedPrivileges;
    private boolean freezePrivileges = true;

    public CreateAuthTokenRequest() {
        super();
    }

    public CreateAuthTokenRequest(RequestedPrivileges requestedPrivileges) {
        super();
        this.requestedPrivileges = requestedPrivileges;

    }

    public CreateAuthTokenRequest(StreamInput in) throws IOException {
        super(in);
        this.tokenName = in.readString();
        this.audience = in.readOptionalString();

        String expiresAfter = in.readOptionalString();

        try {
            this.expiresAfter = TemporalAmountFormat.INSTANCE.parse(expiresAfter);
        } catch (ConfigValidationException e) {
            throw new IOException("Error while parsing " + expiresAfter, e);
        }
        this.requestedPrivileges = new RequestedPrivileges(in);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(tokenName);
        out.writeOptionalString(audience);
        out.writeOptionalString(TemporalAmountFormat.INSTANCE.format(expiresAfter));
        requestedPrivileges.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public static CreateAuthTokenRequest parse(BytesReference document, XContentType contentType) throws ConfigValidationException {
        ValidationErrors validationErrors = new ValidationErrors();
        ValidatingJsonNode vJsonNode = new ValidatingJsonNode(ValidatingJsonParser.readTree(document, contentType), validationErrors);
        CreateAuthTokenRequest result = new CreateAuthTokenRequest();

        result.tokenName = vJsonNode.string("name");
        result.audience = vJsonNode.string("audience");
        result.expiresAfter = vJsonNode.temporalAmount("expires_after");
        result.freezePrivileges = vJsonNode.booleanAttribute("freeze_privileges", Boolean.TRUE);

        if (vJsonNode.hasNonNull("requested")) {
            try {
                result.requestedPrivileges = RequestedPrivileges.parse(vJsonNode.get("requested"));
            } catch (ConfigValidationException e) {
                validationErrors.add("requested", e);
            }
        } else {
            validationErrors.add(new MissingAttribute("requested", vJsonNode));
        }

        validationErrors.throwExceptionForPresentErrors();

        return result;
    }

    public RequestedPrivileges getRequestedPrivileges() {
        return requestedPrivileges;
    }

    public void setRequestedPrivileges(RequestedPrivileges requestedPrivileges) {
        this.requestedPrivileges = requestedPrivileges;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public TemporalAmount getExpiresAfter() {
        return expiresAfter;
    }

    public void setExpiresAfter(Duration expiresAfter) {
        this.expiresAfter = expiresAfter;
    }

    public String getTokenName() {
        return tokenName;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    public boolean isFreezePrivileges() {
        return freezePrivileges;
    }

    public void setFreezePrivileges(boolean snapshotPrivileges) {
        this.freezePrivileges = snapshotPrivileges;
    }

    public String toJson() {
        return Strings.toString(this);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (tokenName != null) {
            builder.field("name", tokenName);
        }

        if (expiresAfter != null) {
            builder.field("expires_after", TemporalAmountFormat.INSTANCE.format(expiresAfter));
        }

        if (requestedPrivileges != null) {
            builder.field("requested", requestedPrivileges);
        }

        builder.field("freeze_privileges", freezePrivileges);

        builder.endObject();
        return builder;
    }

    @Override
    public String toString() {
        return "CreateAuthTokenRequest [tokenName=" + tokenName + ", audience=" + audience + ", expiresAfter=" + expiresAfter
                + ", requestedPrivileges=" + requestedPrivileges + ", freezePrivileges=" + freezePrivileges + "]";
    }

}

