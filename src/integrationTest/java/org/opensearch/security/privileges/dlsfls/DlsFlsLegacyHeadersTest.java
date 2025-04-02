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
package org.opensearch.security.privileges.dlsfls;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.CheckedFunction;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.RangeQueryBuilder;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.search.internal.ShardSearchRequest;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.util.MockIndexMetadataBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.transport.Transport;

import org.mockito.Mockito;

import static org.opensearch.security.Song.ARTIST_STRING;
import static org.opensearch.security.Song.ARTIST_TWINS;
import static org.opensearch.security.Song.FIELD_ARTIST;
import static org.opensearch.security.Song.FIELD_STARS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class DlsFlsLegacyHeadersTest {
    static NamedXContentRegistry xContentRegistry = new NamedXContentRegistry(
        ImmutableList.of(
            new NamedXContentRegistry.Entry(
                QueryBuilder.class,
                new ParseField(TermQueryBuilder.NAME),
                (CheckedFunction<XContentParser, TermQueryBuilder, IOException>) (p) -> TermQueryBuilder.fromXContent(p)
            ),
            new NamedXContentRegistry.Entry(
                QueryBuilder.class,
                new ParseField(MatchQueryBuilder.NAME),
                (CheckedFunction<XContentParser, MatchQueryBuilder, IOException>) (p) -> MatchQueryBuilder.fromXContent(p)
            ),
            new NamedXContentRegistry.Entry(
                QueryBuilder.class,
                new ParseField(RangeQueryBuilder.NAME),
                (CheckedFunction<XContentParser, RangeQueryBuilder, IOException>) (p) -> RangeQueryBuilder.fromXContent(p)
            )
        )
    );

    /**
     * Basic test that the DLS header matches the one produced in previous versions.
     * <p>
     * Test configuration corresponds to DlsIntegrationTests.testShouldSearchI1_S2I2_S3()
     */
    @Test
    public void dls_simple() throws Exception {
        SecurityDynamicConfiguration<RoleV7> rolesConfig = TestSecurityConfig.Role.toRolesConfiguration(
            new TestSecurityConfig.Role("read_where_field_artist_matches_artist_string").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_STRING))
                .on("*")
        );

        Metadata metadata = MockIndexMetadataBuilder.indices("first-test-index", "second-test-index", "my_index1").build();
        DlsFlsProcessedConfig dlsFlsProcessedConfig = dlsFlsProcessedConfig(rolesConfig, metadata);
        String header = new DlsFlsLegacyHeaders(
            ctx(metadata, "read_where_field_artist_matches_artist_string"),
            dlsFlsProcessedConfig,
            metadata,
            false
        ).getDlsHeader();

        // Created with DlsIntegrationTests.testShouldSearchI1_S2I2_S3() on an earlier OpenSearch version
        String expectedHeader =
            "rO0ABXNyACVqYXZhLnV0aWwuQ29sbGVjdGlvbnMkVW5tb2RpZmlhYmxlTWFw8aWo/nT1B0ICAAFMAAFtdAAPTGphdmEvdXRpbC9NYXA7eHBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAAA3QAEGZpcnN0LXRlc3QtaW5kZXhzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAF0AB17Im1hdGNoIjp7ImFydGlzdCI6IlN0cmluZyJ9fXh0AAlteV9pbmRleDFzcQB+AAZ3DAAAABA/QAAAAAAAAXEAfgAIeHQAEXNlY29uZC10ZXN0LWluZGV4c3EAfgAGdwwAAAAQP0AAAAAAAAFxAH4ACHh4";

        assertEquals(Base64Helper.deserializeObject(expectedHeader), Base64Helper.deserializeObject(header));
    }

    /**
     * Test that the DLS header matches the one produced in previous versions. In this case, two roles need to be considered.
     * <p>
     * Test configuration corresponds to DlsIntegrationTests.testShouldSearchI1_S3I1_S6I2_S2()
     */
    @Test
    public void dls_twoRoles() throws Exception {
        SecurityDynamicConfiguration<RoleV7> rolesConfig = TestSecurityConfig.Role.toRolesConfiguration(
            new TestSecurityConfig.Role("read_where_field_artist_matches_artist_twins").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_TWINS))
                .on("*"),
            new TestSecurityConfig.Role("read_where_field_stars_greater_than_five").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls(String.format("{\"range\":{\"%s\":{\"gt\":%d}}}", FIELD_STARS, 5))
                .on("*")
        );

        Metadata metadata = MockIndexMetadataBuilder.indices("first-test-index", "second-test-index", "my_index1").build();
        DlsFlsProcessedConfig dlsFlsProcessedConfig = dlsFlsProcessedConfig(rolesConfig, metadata);
        String header = new DlsFlsLegacyHeaders(
            ctx(metadata, "read_where_field_artist_matches_artist_twins", "read_where_field_stars_greater_than_five"),
            dlsFlsProcessedConfig,
            metadata,
            false
        ).getDlsHeader();

        // Created with DlsIntegrationTests.testShouldSearchI1_S3I1_S6I2_S2() on an earlier OpenSearch version
        String expectedHeader =
            "rO0ABXNyACVqYXZhLnV0aWwuQ29sbGVjdGlvbnMkVW5tb2RpZmlhYmxlTWFw8aWo/nT1B0ICAAFMAAFtdAAPTGphdmEvdXRpbC9NYXA7eHBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAAA3QAEGZpcnN0LXRlc3QtaW5kZXhzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAJ0ABx7Im1hdGNoIjp7ImFydGlzdCI6IlR3aW5zIn19dAAceyJyYW5nZSI6eyJzdGFycyI6eyJndCI6NX19fXh0AAlteV9pbmRleDFzcQB+AAZ3DAAAABA/QAAAAAAAAnEAfgAIcQB+AAl4dAARc2Vjb25kLXRlc3QtaW5kZXhzcQB+AAZ3DAAAABA/QAAAAAAAAnEAfgAIcQB+AAl4eA==";

        assertEquals(Base64Helper.deserializeObject(expectedHeader), Base64Helper.deserializeObject(header));
    }

    @Test
    public void dls_none() throws Exception {
        SecurityDynamicConfiguration<RoleV7> rolesConfig = TestSecurityConfig.Role.toRolesConfiguration(
            new TestSecurityConfig.Role("role").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").on("*")
        );

        Metadata metadata = MockIndexMetadataBuilder.indices("first-test-index", "second-test-index", "my_index1").build();
        DlsFlsProcessedConfig dlsFlsProcessedConfig = dlsFlsProcessedConfig(rolesConfig, metadata);
        String header = new DlsFlsLegacyHeaders(ctx(metadata, "role"), dlsFlsProcessedConfig, metadata, false).getDlsHeader();

        assertNull(header);
    }

    /**
     * Basic test that the FLS header matches the one produced in previous versions.
     * <p>
     * Test configuration corresponds to FlsAndFieldMaskingTests.flsEnabledFieldsAreHiddenForNormalUsers()
     */
    @Test
    public void fls_simple() throws Exception {
        SecurityDynamicConfiguration<RoleV7> rolesConfig = TestSecurityConfig.Role.toRolesConfiguration(
            new TestSecurityConfig.Role("fls_exclude_stars_reader").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .fls("~stars")
                .on("*")
        );

        Metadata metadata = MockIndexMetadataBuilder.indices("first-test-index", "second-test-index", "fls_index").build();
        DlsFlsProcessedConfig dlsFlsProcessedConfig = dlsFlsProcessedConfig(rolesConfig, metadata);
        String header = new DlsFlsLegacyHeaders(ctx(metadata, "fls_exclude_stars_reader"), dlsFlsProcessedConfig, metadata, false)
            .getFlsHeader();

        // Created with FlsAndFieldMaskingTests.flsEnabledFieldsAreHiddenForNormalUsers() on an earlier OpenSearch version
        String expectedHeader =
            "rO0ABXNyACVqYXZhLnV0aWwuQ29sbGVjdGlvbnMkVW5tb2RpZmlhYmxlTWFw8aWo/nT1B0ICAAFMAAFtdAAPTGphdmEvdXRpbC9NYXA7eHBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAAA3QAEGZpcnN0LXRlc3QtaW5kZXhzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAF0AAZ+c3RhcnN4dAAJZmxzX2luZGV4c3EAfgAGdwwAAAAQP0AAAAAAAAFxAH4ACHh0ABFzZWNvbmQtdGVzdC1pbmRleHNxAH4ABncMAAAAED9AAAAAAAABcQB+AAh4eA==";

        assertEquals(Base64Helper.deserializeObject(expectedHeader), Base64Helper.deserializeObject(header));
    }

    /**
     * Test that the FLS header matches the one produced in previous versions. In this case, inclusion and exclusion is mixed
     * and contradicts itself.
     * <p>
     * Test configuration corresponds to FlsAndFieldMaskingTests.testGetDocumentWithNoTitleFieldAndOnlyTitleFieldFLSRestrictions()
     */
    @Test
    public void fls_mixedContradiction() throws Exception {
        SecurityDynamicConfiguration<RoleV7> rolesConfig = TestSecurityConfig.Role.toRolesConfiguration(
            new TestSecurityConfig.Role("example_inclusive_fls").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .fls("title")
                .on("first-test-index"),
            new TestSecurityConfig.Role("example_exclusive_fls").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .fls(String.format("~title"))
                .on("first-test-index")
        );

        Metadata metadata = MockIndexMetadataBuilder.indices("first-test-index", "second-test-index", "fls_index").build();
        DlsFlsProcessedConfig dlsFlsProcessedConfig = dlsFlsProcessedConfig(rolesConfig, metadata);
        String header = new DlsFlsLegacyHeaders(
            ctx(metadata, "example_inclusive_fls", "example_exclusive_fls"),
            dlsFlsProcessedConfig,
            metadata,
            false
        ).getFlsHeader();

        // Created with FlsAndFieldMaskingTests.testGetDocumentWithNoTitleFieldAndOnlyTitleFieldFLSRestrictions() on an earlier OpenSearch
        // version
        String expectedHeader =
            "rO0ABXNyACVqYXZhLnV0aWwuQ29sbGVjdGlvbnMkVW5tb2RpZmlhYmxlTWFw8aWo/nT1B0ICAAFMAAFtdAAPTGphdmEvdXRpbC9NYXA7eHBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAAAXQAEGZpcnN0LXRlc3QtaW5kZXhzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAJ0AAV0aXRsZXQABn50aXRsZXh4";

        assertEquals(Base64Helper.deserializeObject(expectedHeader), Base64Helper.deserializeObject(header));
    }

    /**
     * Basic test that the field masking header matches the one produced in previous versions.
     * <p>
     * Test configuration corresponds to FlsAndFieldMaskingTests.searchForDocuments()
     */
    @Test
    public void fieldMasking_simple() throws Exception {
        SecurityDynamicConfiguration<RoleV7> rolesConfig = TestSecurityConfig.Role.toRolesConfiguration(
            new TestSecurityConfig.Role("masked_title_artist_lyrics_reader").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .maskedFields("artist::/(?<=.{1})./::*", "lyrics::/(?<=.{1})./::*")
                .on("first-test-index"),
            new TestSecurityConfig.Role("masked_lyrics_reader").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .maskedFields("lyrics::/(?<=.{1})./::*")
                .on("second-test-index")
        );

        Metadata metadata = MockIndexMetadataBuilder.indices("first-test-index", "second-test-index").build();
        DlsFlsProcessedConfig dlsFlsProcessedConfig = dlsFlsProcessedConfig(rolesConfig, metadata);
        String header = new DlsFlsLegacyHeaders(
            ctx(metadata, "masked_title_artist_lyrics_reader", "masked_lyrics_reader"),
            dlsFlsProcessedConfig,
            metadata,
            false
        ).getFmHeader();

        // Created with FlsAndFieldMaskingTests.flsEnabledFieldsAreHiddenForNormalUsers() on an earlier OpenSearch version
        String expectedHeader =
            "rO0ABXNyACVqYXZhLnV0aWwuQ29sbGVjdGlvbnMkVW5tb2RpZmlhYmxlTWFw8aWo/nT1B0ICAAFMAAFtdAAPTGphdmEvdXRpbC9NYXA7eHBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAAAnQAEGZpcnN0LXRlc3QtaW5kZXhzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAJ0ABdhcnRpc3Q6Oi8oPzw9LnsxfSkuLzo6KnQAF2x5cmljczo6Lyg/PD0uezF9KS4vOjoqeHQAEXNlY29uZC10ZXN0LWluZGV4c3EAfgAGdwwAAAAQP0AAAAAAAAF0ABdseXJpY3M6Oi8oPzw9LnsxfSkuLzo6Knh4";

        assertEquals(Base64Helper.deserializeObject(expectedHeader), Base64Helper.deserializeObject(header));
    }

    @Test
    public void performHeaderDecoration_oldNode() throws Exception {
        Metadata metadata = exampleMetadata();
        DlsFlsProcessedConfig dlsFlsProcessedConfig = dlsFlsProcessedConfig(exampleRolesConfig(), metadata);

        Transport.Connection connection = Mockito.mock(Transport.Connection.class);
        Mockito.when(connection.getVersion()).thenReturn(Version.V_2_0_0);

        // ShardSearchRequest does not extend ActionRequest, thus the headers must be set
        ShardSearchRequest request = Mockito.mock(ShardSearchRequest.class);

        Map<String, String> headerSink = new HashMap<>();

        DlsFlsLegacyHeaders subject = new DlsFlsLegacyHeaders(ctx(metadata, "test_role"), dlsFlsProcessedConfig, metadata, false);

        subject.performHeaderDecoration(connection, request, headerSink);

        assertEquals(subject.getDlsHeader(), headerSink.get(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER));
        assertEquals(subject.getFlsHeader(), headerSink.get(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER));
        assertEquals(subject.getFmHeader(), headerSink.get(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER));
    }

    @Test
    public void performHeaderDecoration_actionRequest() throws Exception {
        Metadata metadata = exampleMetadata();
        DlsFlsProcessedConfig dlsFlsProcessedConfig = dlsFlsProcessedConfig(exampleRolesConfig(), metadata);

        Transport.Connection connection = Mockito.mock(Transport.Connection.class);
        Mockito.when(connection.getVersion()).thenReturn(Version.V_2_0_0);

        // SearchRequest does extend ActionRequest, thus the headers must not be set
        SearchRequest request = new SearchRequest();

        Map<String, String> headerSink = new HashMap<>();

        DlsFlsLegacyHeaders subject = new DlsFlsLegacyHeaders(ctx(metadata, "test_role"), dlsFlsProcessedConfig, metadata, false);

        subject.performHeaderDecoration(connection, request, headerSink);
        assertEquals(0, headerSink.size());
    }

    @Test
    public void performHeaderDecoration_newNode() throws Exception {
        Metadata metadata = exampleMetadata();
        DlsFlsProcessedConfig dlsFlsProcessedConfig = dlsFlsProcessedConfig(exampleRolesConfig(), metadata);

        Transport.Connection connection = Mockito.mock(Transport.Connection.class);
        Mockito.when(connection.getVersion()).thenReturn(Version.V_3_0_0);

        // ShardSearchRequest does not extend ActionRequest, thus the headers must be set
        ShardSearchRequest request = Mockito.mock(ShardSearchRequest.class);

        Map<String, String> headerSink = new HashMap<>();

        DlsFlsLegacyHeaders subject = new DlsFlsLegacyHeaders(ctx(metadata, "test_role"), dlsFlsProcessedConfig, metadata, false);

        subject.performHeaderDecoration(connection, request, headerSink);
        assertEquals(0, headerSink.size());
    }

    @Test
    public void prepare() throws Exception {
        Metadata metadata = exampleMetadata();

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);

        DlsFlsLegacyHeaders.prepare(
            threadContext,
            ctx(metadata, "test_role"),
            dlsFlsProcessedConfig(exampleRolesConfig(), metadata),
            metadata,
            false
        );
        DlsFlsLegacyHeaders instance = threadContext.getTransient(DlsFlsLegacyHeaders.TRANSIENT_HEADER);

        assertNotNull(instance);
    }

    @Test
    public void prepare_ccs() throws Exception {
        Metadata metadata = exampleMetadata();

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST, true);
        User user = new User("test_user");
        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(metadata).build();

        PrivilegesEvaluationContext ctx = new PrivilegesEvaluationContext(
            user,
            ImmutableSet.of("test_role"),
            null,
            new ClusterSearchShardsRequest(),
            null,
            null,
            new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY)),
            () -> clusterState
        );

        DlsFlsLegacyHeaders.prepare(threadContext, ctx, dlsFlsProcessedConfig(exampleRolesConfig(), metadata), metadata, false);
        assertTrue(threadContext.getResponseHeaders().containsKey(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER));
    }

    static PrivilegesEvaluationContext ctx(Metadata metadata, String... roles) {
        User user = new User("test_user");
        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(metadata).build();

        return new PrivilegesEvaluationContext(
            user,
            ImmutableSet.copyOf(roles),
            null,
            null,
            null,
            null,
            new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY)),
            () -> clusterState
        );
    }

    static DlsFlsProcessedConfig dlsFlsProcessedConfig(SecurityDynamicConfiguration<RoleV7> rolesConfig, Metadata metadata) {
        return new DlsFlsProcessedConfig(
            rolesConfig,
            metadata.getIndicesLookup(),
            xContentRegistry,
            Settings.EMPTY,
            FieldMasking.Config.DEFAULT
        );
    }

    static SecurityDynamicConfiguration<RoleV7> exampleRolesConfig() {
        return TestSecurityConfig.Role.toRolesConfiguration(
            new TestSecurityConfig.Role("test_role").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls("{\"match\":{\"artist\":\"foo\"}}")
                .fls("~stars")
                .maskedFields("foo")
                .on("*")
        );
    }

    static Metadata exampleMetadata() {
        return MockIndexMetadataBuilder.indices("first-test-index", "second-test-index").build();
    }
}
