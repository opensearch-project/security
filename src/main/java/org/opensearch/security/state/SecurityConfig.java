/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.security.state;

import java.io.IOException;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.securityconf.impl.CType;

import static java.time.format.DateTimeFormatter.ISO_INSTANT;

public class SecurityConfig implements Writeable, ToXContent {

    private final CType type;

    private final Instant lastModified;

    private final String hash;

    public SecurityConfig(final CType type, final String hash, final Instant lastModified) {
        this.type = type;
        this.hash = hash;
        this.lastModified = lastModified;
    }

    public SecurityConfig(final StreamInput in) throws IOException {
        this.type = in.readEnum(CType.class);
        this.hash = in.readString();
        this.lastModified = in.readOptionalInstant();
    }

    public Optional<Instant> lastModified() {
        return Optional.ofNullable(lastModified);
    }

    public CType type() {
        return type;
    }

    public String hash() {
        return hash;
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeEnum(type);
        out.writeString(hash);
        out.writeOptionalInstant(lastModified);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder xContentBuilder, final Params params) throws IOException {
        xContentBuilder.startObject(type.toLCString()).field("hash", hash);
        if (lastModified != null) {
            xContentBuilder.field("last_modified", ISO_INSTANT.format(lastModified));
        } else {
            xContentBuilder.nullField("last_modified");
        }
        return xContentBuilder.endObject();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityConfig that = (SecurityConfig) o;
        return type == that.type && Objects.equals(lastModified, that.lastModified) && Objects.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, lastModified, hash);
    }

    public final static class Builder {

        private final CType type;

        private Instant lastModified;

        private String hash;

        Builder(final SecurityConfig securityConfig) {
            this.type = securityConfig.type;
            this.lastModified = securityConfig.lastModified;
            this.hash = securityConfig.hash;
        }

        public Builder withHash(final String hash) {
            this.hash = hash;
            return this;
        }

        public Builder withLastModified(final Instant lastModified) {
            this.lastModified = lastModified;
            return this;
        }

        public SecurityConfig build() {
            return new SecurityConfig(type, hash, lastModified);
        }

    }

    public static SecurityConfig.Builder from(final SecurityConfig securityConfig) {
        return new SecurityConfig.Builder(securityConfig);
    }

}
