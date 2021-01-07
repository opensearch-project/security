package com.amazon.dlic.auth.http.jwt.authtoken.api.config;

import java.io.IOException;
import java.io.Serializable;

import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.ConfigValidationException;
import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.ValidatingJsonNode;
import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.ValidationErrors;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;

import com.fasterxml.jackson.databind.JsonNode;

public class ConfigVersion implements ToXContentObject, Writeable, Serializable {

    private static final long serialVersionUID = -3369133843964881336L;
    private final CType configurationType;
    private final long version;

    public ConfigVersion(CType configurationType, long version) {
        if (version <= 0) {
            throw new IllegalArgumentException("version must be not <= 0: " + version + "; configurationType: " + configurationType);
        }

        this.configurationType = configurationType;
        this.version = version;
    }

    public ConfigVersion(StreamInput in) throws IOException {
        this.configurationType = in.readEnum(CType.class);
        this.version = in.readLong();
    }

    public CType getConfigurationType() {
        return configurationType;
    }

    public long getVersion() {
        return version;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((configurationType == null) ? 0 : configurationType.hashCode());
        result = prime * result + (int) (version ^ (version >>> 32));
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
        ConfigVersion other = (ConfigVersion) obj;
        if (configurationType != other.configurationType)
            return false;
        if (version != other.version)
            return false;
        return true;
    }

    @Override
    public String toString() {
        return configurationType.name() + "@" + version;
    }

    public String toId() {
        return configurationType.name() + "_" + version;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("type", configurationType.name());
        builder.field("version", version);
        builder.endObject();
        return builder;
    }

    public static ConfigVersion fromId(String id) {
        int u = id.lastIndexOf('_');

        if (u == -1) {
            throw new IllegalArgumentException("Invalid ConfigurationVersion id: " + id);
        }

        try {
            long version = Long.parseLong(id.substring(u + 1));

            return new ConfigVersion(CType.valueOf(id.substring(0, u)), version);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid ConfigurationVersion id: " + id, e);

        }
    }

    public static ConfigVersion parse(JsonNode jsonNode) throws ConfigValidationException {
        ValidationErrors validationErrors = new ValidationErrors();
        ValidatingJsonNode vJsonNode = new ValidatingJsonNode(jsonNode, validationErrors);

        CType configType = vJsonNode.requiredCaseInsensitiveEnum("type", CType.class);
        long version = vJsonNode.requiredInt("version");

        validationErrors.throwExceptionForPresentErrors();

        return new ConfigVersion(configType, version);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(this.configurationType);
        out.writeLong(this.version);
    }

}

