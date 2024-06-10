/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.state;

import java.io.IOException;
import java.time.Instant;
import java.util.Comparator;
import java.util.Objects;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedSet;

import org.opensearch.Version;
import org.opensearch.cluster.AbstractNamedDiffable;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.NamedDiff;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentBuilder;

import static java.time.format.DateTimeFormatter.ISO_INSTANT;

public final class SecurityMetadata extends AbstractNamedDiffable<ClusterState.Custom> implements ClusterState.Custom {

    public final static String TYPE = "security";

    private final Instant created;

    private final Set<SecurityConfig> configuration;

    public SecurityMetadata(final Instant created, final Set<SecurityConfig> configuration) {
        this.created = created;
        this.configuration = configuration;
    }

    public SecurityMetadata(StreamInput in) throws IOException {
        this.created = in.readInstant();
        this.configuration = in.readSet(SecurityConfig::new);
    }

    public Instant created() {
        return created;
    }

    public Set<SecurityConfig> configuration() {
        return configuration;
    }

    @Override
    public Version getMinimalSupportedVersion() {
        return Version.CURRENT.minimumCompatibilityVersion();
    }

    @Override
    public String getWriteableName() {
        return TYPE;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeInstant(created);
        out.writeCollection(configuration);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.field("created", ISO_INSTANT.format(created));
        xContentBuilder.startObject("configuration");
        for (final var securityConfig : configuration) {
            securityConfig.toXContent(xContentBuilder, EMPTY_PARAMS);
        }
        return xContentBuilder.endObject();
    }

    public static NamedDiff<ClusterState.Custom> readDiffFrom(StreamInput in) throws IOException {
        return readDiffFrom(ClusterState.Custom.class, TYPE, in);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityMetadata that = (SecurityMetadata) o;
        return Objects.equals(created, that.created) && Objects.equals(configuration, that.configuration);
    }

    @Override
    public int hashCode() {
        return Objects.hash(created, configuration);
    }

    public final static class Builder {

        private final Instant created;

        private final ImmutableSet.Builder<SecurityConfig> configuration = new ImmutableSortedSet.Builder<>(
            Comparator.comparing(SecurityConfig::type)
        );

        Builder(SecurityMetadata oldMetadata) {
            this.created = oldMetadata.created;
            this.configuration.addAll(oldMetadata.configuration);
        }

        public Builder withSecurityConfig(final SecurityConfig securityConfig) {
            this.configuration.add(securityConfig);
            return this;
        }

        public SecurityMetadata build() {
            return new SecurityMetadata(created, configuration.build());
        }

    }

    public static SecurityMetadata.Builder from(final SecurityMetadata securityMetadata) {
        return new SecurityMetadata.Builder(securityMetadata);
    }

}
