package com.amazon.opendistroforelasticsearch.security.authtoken;

import com.amazon.opendistroforelasticsearch.security.authtoken.validation.ConfigValidationException;
import com.amazon.opendistroforelasticsearch.security.authtoken.validation.MissingAttribute;
import com.amazon.opendistroforelasticsearch.security.authtoken.validation.ValidatingJsonNode;
import com.amazon.opendistroforelasticsearch.security.authtoken.validation.ValidationErrors;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.io.Serializable;
import java.time.Instant;
import java.util.Map;

public class AuthToken implements ToXContentObject, Writeable, Serializable {
    private static final Logger log = LogManager.getLogger(AuthToken.class);

    public static final Map<String, Object> INDEX_MAPPING = ImmutableMap.of("dynamic", true, "properties",
            ImmutableMap.of("created_at", ImmutableMap.of("type", "date"), "expires_at", ImmutableMap.of("type", "date")));

    private static final long serialVersionUID = 6038589333544878668L;
    private final String userName;
    private final String tokenName;
    private final String id;
    private final Instant creationTime;
    private final Instant expiryTime;
    private final Instant revokedAt;

    //private final RequestedPrivileges requestedPrivileges;
    //private final AuthTokenPrivilegeBase base;

    AuthToken(String id, String userName, String tokenName,
              //RequestedPrivileges requestedPrivileges, AuthTokenPrivilegeBase base,
              Instant creationTime,
              Instant expiryTime, Instant revokedAt) {
        this.id = id;
        this.userName = userName;
        this.tokenName = tokenName;
        //this.requestedPrivileges = requestedPrivileges;
        //this.base = base;
        this.creationTime = creationTime;
        this.expiryTime = expiryTime;
        this.revokedAt = revokedAt;
    }

    public AuthToken(StreamInput in) throws IOException {
        this.id = in.readString();
        this.userName = in.readString();
        this.tokenName = in.readOptionalString();
        this.creationTime = in.readInstant();
        this.expiryTime = in.readOptionalInstant();
        this.revokedAt = in.readOptionalInstant();

        //this.requestedPrivileges = new RequestedPrivileges(in);
        //this.base = new AuthTokenPrivilegeBase(in);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        toXContentFragment(builder, params);
        builder.endObject();
        return builder;
    }

    public XContentBuilder toXContentFragment(XContentBuilder builder, Params params) throws IOException {
        log.info("userName " + userName);
        log.info("tokenName "  + tokenName);
        log.info("created_at " + creationTime.toEpochMilli());


        builder.field("user_name", userName);
        builder.field("token_name", tokenName);

        //builder.field("requested", requestedPrivileges);
        //builder.field("base");
        //base.toXContent(builder, params);

        builder.field("created_at", creationTime.toEpochMilli());

        if (expiryTime != null) {
            builder.field("expires_at", expiryTime.toEpochMilli());
        }

        if (revokedAt != null) {
            builder.field("revoked_at", revokedAt.toEpochMilli());
        }

        return builder;
    }

    public String getId() {
        return id;
    }

    /*public RequestedPrivileges getRequestedPrivileges() {
        return requestedPrivileges;
    }*/

    public String getUserName() {
        return userName;
    }

    public String getTokenName() {
        return tokenName;
    }

    /*public AuthTokenPrivilegeBase getBase() {
        return base;
    }*/

    public boolean isRevoked() {
        return revokedAt != null;
    }

    AuthToken getRevokedInstance() {
        AuthToken revoked = new AuthToken(id, userName, tokenName,
                //requestedPrivileges, base,
                creationTime, expiryTime, Instant.now());
        //revoked.getBase().setConfigSnapshot(null);
        return revoked;
    }

    public static AuthToken parse(String id, JsonNode jsonNode) throws ConfigValidationException {
        ValidationErrors validationErrors = new ValidationErrors();
        ValidatingJsonNode vJsonNode = new ValidatingJsonNode(jsonNode, validationErrors);

        String userName = vJsonNode.requiredString("user_name");
        String tokenName = vJsonNode.string("token_name");
        //AuthTokenPrivilegeBase base = null;
        //RequestedPrivileges requestedPrivilges = null;

        if (vJsonNode.hasNonNull("base")) {
            /*try {
                base = AuthTokenPrivilegeBase.parse(vJsonNode.get("base"));
            } catch (ConfigValidationException e) {
                validationErrors.add("base", e);
            }*/
        } else {
            validationErrors.add(new MissingAttribute("base", jsonNode));
        }

        if (vJsonNode.hasNonNull("requested")) {
           /* try {
                requestedPrivilges = RequestedPrivileges.parse(vJsonNode.get("requested"));
            } catch (ConfigValidationException e) {
                validationErrors.add("requested", e);
            }*/
        } else {
            validationErrors.add(new MissingAttribute("requested", jsonNode));
        }

        Instant createdAt = vJsonNode.requiredValue("created_at", (v) -> Instant.ofEpochMilli(v.longValue()));
        Instant expiry = vJsonNode.value("expires_at", (v) -> Instant.ofEpochMilli(v.longValue()), null);
        Instant revokedAt = vJsonNode.value("revoked_at", (v) -> Instant.ofEpochMilli(v.longValue()), null);

        validationErrors.throwExceptionForPresentErrors();

        return new AuthToken(id, userName, tokenName, createdAt, expiry, revokedAt);
    }

    public Instant getCreationTime() {
        return creationTime;
    }

    public Instant getExpiryTime() {
        return expiryTime;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.id);
        out.writeString(this.userName);
        out.writeOptionalString(this.tokenName);
        out.writeInstant(this.creationTime);
        out.writeOptionalInstant(this.expiryTime);
        out.writeOptionalInstant(this.revokedAt);
        //this.requestedPrivileges.writeTo(out);
        //this.base.writeTo(out);
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    @Override
    public String toString() {
        return "AuthToken [userName=" + userName + ", tokenName=" + tokenName + ", id=" + id + ", creationTime=" + creationTime + ", expiryTime="
                + expiryTime + ", revokedAt=" + revokedAt + //", requestedPrivilges=" + requestedPrivileges + ", base=" + base
         "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        //result = prime * result + ((base == null) ? 0 : base.hashCode());
        result = prime * result + ((creationTime == null) ? 0 : creationTime.hashCode());
        result = prime * result + ((expiryTime == null) ? 0 : expiryTime.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        //result = prime * result + ((requestedPrivileges == null) ? 0 : requestedPrivileges.hashCode());
        result = prime * result + ((tokenName == null) ? 0 : tokenName.hashCode());
        result = prime * result + ((userName == null) ? 0 : userName.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AuthToken other = (AuthToken) obj;
        /*if (base == null) {
            if (other.base != null)
                return false;
        } else if (!base.equals(other.base))
            return false;*/
        if (creationTime == null) {
            if (other.creationTime != null)
                return false;
        } else if (!creationTime.equals(other.creationTime))
            return false;
        if (expiryTime == null) {
            if (other.expiryTime != null)
                return false;
        } else if (!expiryTime.equals(other.expiryTime))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        /*if (requestedPrivileges == null) {
            if (other.requestedPrivileges != null)
                return false;
        } else if (!requestedPrivileges.equals(other.requestedPrivileges))
            return false;*/
        if (tokenName == null) {
            if (other.tokenName != null)
                return false;
        } else if (!tokenName.equals(other.tokenName))
            return false;
        if (userName == null) {
            if (other.userName != null)
                return false;
        } else if (!userName.equals(other.userName))
            return false;
        return true;
    }

}
