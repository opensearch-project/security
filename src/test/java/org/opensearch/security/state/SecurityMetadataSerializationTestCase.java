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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import com.carrotsearch.randomizedtesting.RandomizedContext;
import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.RandomizedTest;
import com.google.common.collect.ImmutableSortedSet;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.Version;
import org.opensearch.cluster.ClusterState;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.NamedWriteableAwareStreamInput;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.test.DiffableTestUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

@RunWith(RandomizedRunner.class)
public class SecurityMetadataSerializationTestCase extends RandomizedTest {

    protected ClusterState.Custom createTestInstance() {
        final var configuration = new ImmutableSortedSet.Builder<>(Comparator.comparing(SecurityConfig::type));
        for (final var c : CType.values()) {
            configuration.add(new SecurityConfig(c, randomAsciiAlphanumOfLength(128), null));
        }
        return new SecurityMetadata(randomInstant(), configuration.build());
    }

    protected ClusterState.Custom makeTestChanges(ClusterState.Custom custom) {
        final var securityMetadata = (SecurityMetadata) custom;

        if (randomBoolean()) {
            final var configuration = securityMetadata.configuration();
            int leaveElements = randomIntBetween(0, configuration.size() - 1);
            final var randomConfigs = randomSubsetOf(leaveElements, configuration);
            final var securityMetadataBuilder = SecurityMetadata.from(securityMetadata);
            for (final var config : randomConfigs) {
                securityMetadataBuilder.withSecurityConfig(
                    SecurityConfig.from(config).withLastModified(randomInstant()).withHash(randomAsciiAlphanumOfLength(128)).build()
                );
            }
            return securityMetadataBuilder.build();
        }

        return securityMetadata;
    }

    public static <T> List<T> randomSubsetOf(int size, Collection<T> collection) {
        if (size > collection.size()) {
            throw new IllegalArgumentException(
                "Can't pick " + size + " random objects from a collection of " + collection.size() + " objects"
            );
        }
        List<T> tempList = new ArrayList<>(collection);
        Collections.shuffle(tempList, RandomizedContext.current().getRandom());
        return tempList.subList(0, size);
    }

    protected Instant randomInstant() {
        return Instant.ofEpochSecond(randomLongBetween(0L, 3000000000L), randomLongBetween(0L, 999999999L));
    }

    @Test
    public void testSerialization() throws IOException {
        for (int runs = 0; runs < 20; runs++) {
            ClusterState.Custom testInstance = createTestInstance();
            assertSerialization(testInstance);
        }
    }

    void assertSerialization(ClusterState.Custom testInstance) throws IOException {
        assertSerialization(testInstance, Version.CURRENT);
    }

    void assertSerialization(ClusterState.Custom testInstance, Version version) throws IOException {
        ClusterState.Custom deserializedInstance = copyInstance(testInstance, version);
        assertEqualInstances(testInstance, deserializedInstance);
    }

    void assertEqualInstances(ClusterState.Custom expectedInstance, ClusterState.Custom newInstance) {
        assertNotSame(newInstance, expectedInstance);
        assertEquals(expectedInstance, newInstance);
        assertEquals(expectedInstance.hashCode(), newInstance.hashCode());
    }

    @Test
    public void testDiffableSerialization() throws IOException {
        DiffableTestUtils.testDiffableSerialization(
            this::createTestInstance,
            this::makeTestChanges,
            getNamedWriteableRegistry(),
            SecurityMetadata::new,
            SecurityMetadata::readDiffFrom
        );
    }

    protected NamedWriteableRegistry getNamedWriteableRegistry() {
        return new NamedWriteableRegistry(Collections.emptyList());
    }

    protected final ClusterState.Custom copyInstance(ClusterState.Custom instance, Version version) throws IOException {
        return copyWriteable(instance, getNamedWriteableRegistry(), SecurityMetadata::new, version);
    }

    public static <T extends Writeable> T copyWriteable(
        T original,
        NamedWriteableRegistry namedWriteableRegistry,
        Writeable.Reader<T> reader,
        Version version
    ) throws IOException {
        return copyInstance(original, namedWriteableRegistry, (out, value) -> value.writeTo(out), reader, version);
    }

    protected static <T> T copyInstance(
        T original,
        NamedWriteableRegistry namedWriteableRegistry,
        Writeable.Writer<T> writer,
        Writeable.Reader<T> reader,
        Version version
    ) throws IOException {
        try (BytesStreamOutput output = new BytesStreamOutput()) {
            output.setVersion(version);
            writer.write(output, original);
            try (StreamInput in = new NamedWriteableAwareStreamInput(output.bytes().streamInput(), namedWriteableRegistry)) {
                in.setVersion(version);
                return reader.read(in);
            }
        }
    }

}
