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

package org.opensearch.security.auditlog.impl;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.http.HttpChannel;
import org.opensearch.http.HttpRequest;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.securityconf.impl.CType;

import tools.jackson.databind.ObjectMapper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.opensearch.security.auditlog.impl.AuditMessage.SPLIT_MESSAGE_IDENTIFIER;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuditMessageTest {

    private static final Map<String, List<String>> TEST_REST_HEADERS = ImmutableMap.of(
        "authorization",
        ImmutableList.of("test-1"),
        "Authorization",
        ImmutableList.of("test-2"),
        "AuThOrIzAtIoN",
        ImmutableList.of("test-3"),
        "test-header",
        ImmutableList.of("test-4")
    );

    private static final Map<String, String> TEST_TRANSPORT_HEADERS = ImmutableMap.of(
        "authorization",
        "test-1",
        "Authorization",
        "test-2",
        "AuThOrIzAtIoN",
        "test-3",
        "test-header",
        "test-4"
    );

    private final ClusterService clusterServiceMock = mock(ClusterService.class);
    private final DiscoveryNode discoveryNodeMock = mock(DiscoveryNode.class);
    private final ClusterName clusterNameMock = mock(ClusterName.class);
    private final AuditConfig auditConfig = mock(AuditConfig.class);
    private final AuditConfig.Filter auditFilterMock = mock(AuditConfig.Filter.class);

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private AuditMessage message;

    @Before
    public void setUp() {
        when(clusterServiceMock.localNode()).thenReturn(discoveryNodeMock);
        when(clusterServiceMock.getClusterName()).thenReturn(clusterNameMock);
        when(auditConfig.getFilter()).thenReturn(auditFilterMock);
        message = new AuditMessage(AuditCategory.AUTHENTICATED, clusterServiceMock, AuditLog.Origin.REST, AuditLog.Origin.REST);
    }

    @Test
    public void testAuthorizationRestHeadersAreFiltered() {
        when(auditConfig.getFilter().shouldExcludeHeader("test-header")).thenReturn(false);
        message.addRestHeaders(TEST_REST_HEADERS, true, auditConfig.getFilter());
        assertThat(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS), is(ImmutableMap.of("test-header", ImmutableList.of("test-4"))));
    }

    @Test
    public void testCustomRestHeadersAreFiltered() {
        when(auditConfig.getFilter().shouldExcludeHeader("test-header")).thenReturn(true);
        message.addRestHeaders(TEST_REST_HEADERS, true, auditConfig.getFilter());
        assertThat(Map.of(), is(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS)));
    }

    @Test
    public void testRestHeadersNull() {
        message.addRestHeaders(null, true, null);
        assertNull(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS));
        message.addRestHeaders(Collections.emptyMap(), true, null);
        assertNull(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS));
    }

    @Test
    public void testRestHeadersAreNotFiltered() {
        when(auditConfig.getFilter().shouldExcludeHeader("test-header")).thenReturn(false);
        message.addRestHeaders(TEST_REST_HEADERS, false, null);
        assertThat(TEST_REST_HEADERS, is(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS)));
    }

    @Test
    public void testTransportHeadersNull() {
        message.addTransportHeaders(null, true);
        assertNull(message.getAsMap().get(AuditMessage.TRANSPORT_REQUEST_HEADERS));
        message.addTransportHeaders(Collections.emptyMap(), true);
        assertNull(message.getAsMap().get(AuditMessage.TRANSPORT_REQUEST_HEADERS));
    }

    @Test
    public void testTransportHeadersAreFiltered() {
        message.addTransportHeaders(TEST_TRANSPORT_HEADERS, true);
        assertThat(message.getAsMap().get(AuditMessage.TRANSPORT_REQUEST_HEADERS), is(ImmutableMap.of("test-header", "test-4")));
    }

    @Test
    public void testTransportHeadersAreNotFiltered() {
        message.addTransportHeaders(TEST_TRANSPORT_HEADERS, false);
        assertThat(TEST_TRANSPORT_HEADERS, is(message.getAsMap().get(AuditMessage.TRANSPORT_REQUEST_HEADERS)));
    }

    @Test
    public void testBCryptHashIsRedacted() {
        final String internalUsersDocId = CType.INTERNALUSERS.toLCString();
        final String hash1 = "$2y$12$gpTlsqv8yYsbR7P.fFbZ5uYXxUmGY4oLYeJNOMiz23ByrRMNFgBGm";
        final String hash2 = "$2y$12$tPnP6XpeRuBTPXBG1XVJCOsZ4xi6eRs4yFnrbynyoWnYJmfAxTNZ6";

        // does not perform redaction for non-internal user doc
        message.addSecurityConfigContentToRequestBody(hash1, "test-doc");
        assertThat(message.getAsMap().get(AuditMessage.REQUEST_BODY), is(hash1));

        // test hash redaction
        message.addSecurityConfigContentToRequestBody(hash1, internalUsersDocId);
        assertThat(message.getAsMap().get(AuditMessage.REQUEST_BODY), is("__HASH__"));

        // test hash redaction in string
        message.addSecurityConfigContentToRequestBody("Hash " + hash2 + " is redacted", internalUsersDocId);
        assertThat(message.getAsMap().get(AuditMessage.REQUEST_BODY), is("Hash __HASH__ is redacted"));

        // test hash redaction inline without spaces
        message.addSecurityConfigContentToRequestBody("Inline hash" + hash2 + "is redacted", internalUsersDocId);
        assertThat(message.getAsMap().get(AuditMessage.REQUEST_BODY), is("Inline hash__HASH__is redacted"));

        // test map redaction
        message.addSecurityConfigWriteDiffSource("Diff is " + hash2, internalUsersDocId);
        assertThat(message.getAsMap().get(AuditMessage.COMPLIANCE_DIFF_CONTENT), is("Diff is __HASH__"));

        // test tuple redaction
        final ByteBuffer[] byteBuffers = new ByteBuffer[] { ByteBuffer.wrap(("Hash in tuple is " + hash1).getBytes()) };
        BytesReference ref = BytesReference.fromByteBuffers(byteBuffers);
        message.addSecurityConfigTupleToRequestBody(new Tuple<>(XContentType.JSON, ref), internalUsersDocId);
        assertThat(message.getAsMap().get(AuditMessage.REQUEST_BODY), is("Hash in tuple is __HASH__"));
    }

    @Test
    public void testRequestBodyLoggingWithInvalidSourceOrContentTypeParam() {
        when(auditConfig.getFilter().shouldLogRequestBody()).thenReturn(true);

        HttpRequest httpRequest = mock(HttpRequest.class);

        // No content or Source paramater
        when(httpRequest.uri()).thenReturn("");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[0]));

        RestRequest restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        SecurityRequest request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditConfig.getFilter());
        assertNull(message.getAsMap().get(AuditMessage.REQUEST_BODY));

        // No source parameter, content present but Invalid content-type header
        when(httpRequest.uri()).thenReturn("");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[1]));

        restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditConfig.getFilter());
        assertThat(message.getAsMap().get(AuditMessage.REQUEST_BODY), is("ERROR: Unable to generate request body"));

        // No content, source parameter present but Invalid source-content-type parameter
        when(httpRequest.uri()).thenReturn("/aaaa?source=request_body");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[0]));

        restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditConfig.getFilter());
        assertThat(message.getAsMap().get(AuditMessage.REQUEST_BODY), is("ERROR: Unable to generate request body"));
    }

    private AuditMessage dummyAuditMessage(final String[] indices, String[] resolvedIndices) {
        final AuditMessage auditMessage = new AuditMessage(
            AuditCategory.AUTHENTICATED,
            clusterServiceMock,
            AuditLog.Origin.REST,
            AuditLog.Origin.REST
        );

        if (indices != null) {
            auditMessage.addIndices(indices);
        }
        if (resolvedIndices != null) {
            auditMessage.addResolvedIndices(resolvedIndices);
        }
        return auditMessage;
    }

    private String[] getTestIndices(final int indexNameLength, final int numberOfIndices) {
        ArrayList<String> indices = new ArrayList<>();
        for (int i = 0; i < numberOfIndices; i++) {
            indices.add("a".repeat(indexNameLength));
        }
        return indices.toArray(new String[0]);
    }

    private static String getSplitMessageId(final String message) {
        return objectMapper.readTree(message).get(SPLIT_MESSAGE_IDENTIFIER).asText();
    }

    @Test
    public void testToJsonSplitIndices() {
        // test standard case, should be split into 4 messages
        AuditMessage auditMessage = dummyAuditMessage(new String[] { "*" }, getTestIndices(255, 3));
        List<String> splitMessages = auditMessage.toJsonSplitIndices(255);
        assertThat(splitMessages.size(), is(4));
        // all messages share the same ID
        assertThat(splitMessages.stream().map(AuditMessageTest::getSplitMessageId).distinct().count(), is(1L));

        // test when audit_trace_indices is not present, should be split into 3 messages
        auditMessage = dummyAuditMessage(null, getTestIndices(255, 3));
        splitMessages = auditMessage.toJsonSplitIndices(255);
        assertThat(splitMessages.size(), is(3));
        // all messages share the same ID
        assertThat(splitMessages.stream().map(AuditMessageTest::getSplitMessageId).distinct().count(), is(1L));

        // test when splitting isn't required, should return a single message
        auditMessage = dummyAuditMessage(new String[] { "*" }, getTestIndices(255, 2));
        splitMessages = auditMessage.toJsonSplitIndices(700);
        assertThat(splitMessages.size(), is(1));
        // messages that aren't split don't get a split ID
        assertThat(splitMessages.getFirst(), not(containsString(SPLIT_MESSAGE_IDENTIFIER)));

        // test when there aren't enough indices to fill a whole message so some resolved indices are added too.
        // Should be split into 2 messages. First with "*" and one resolved index, second with the remaining resolved indices
        auditMessage = dummyAuditMessage(new String[] { "*" }, getTestIndices(255, 3));
        splitMessages = auditMessage.toJsonSplitIndices(700);
        assertThat(splitMessages.size(), is(2));
        // all messages share the same ID
        assertThat(splitMessages.stream().map(AuditMessageTest::getSplitMessageId).distinct().count(), is(1L));
    }

    // --- Resource Sharing audit field tests ---

    @Test
    public void testAddResourceIdPopulatesField() {
        message.addResourceId("saved-query-123");
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_ID), is("saved-query-123"));
    }

    @Test
    public void testAddResourceIdNullIsIgnored() {
        message.addResourceId(null);
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_ID));
    }

    @Test
    public void testAddResourceIdEmptyIsIgnored() {
        message.addResourceId("");
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_ID));
    }

    @Test
    public void testAddResourceTypePopulatesField() {
        message.addResourceType("dashboard");
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_TYPE), is("dashboard"));
    }

    @Test
    public void testAddResourceTypeNullIsIgnored() {
        message.addResourceType(null);
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_TYPE));
    }

    @Test
    public void testAddResourceIndexPopulatesField() {
        message.addResourceIndex(".plugins-ml-resource-sharing");
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_INDEX), is(".plugins-ml-resource-sharing"));
    }

    @Test
    public void testAddResourceIndexNullIsIgnored() {
        message.addResourceIndex(null);
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_INDEX));
    }

    @Test
    public void testAddResourceAccessResultPopulatesField() {
        message.addResourceAccessResult("granted");
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_ACCESS_RESULT), is("granted"));
    }

    @Test
    public void testAddResourceAccessResultDenied() {
        message.addResourceAccessResult("denied");
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_ACCESS_RESULT), is("denied"));
    }

    @Test
    public void testAddResourceSharingActionPopulatesField() {
        message.addResourceSharingAction("share");
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_SHARING_ACTION), is("share"));
    }

    @Test
    public void testAddResourceSharingActionPatch() {
        message.addResourceSharingAction("patch");
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_SHARING_ACTION), is("patch"));
    }

    @Test
    public void testAddResourceRecipientsAddedPopulatesField() {
        String recipients = "ShareWith {read_write={users=[bob], roles=[analysts]}}";
        message.addResourceRecipientsAdded(recipients);
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_RECIPIENTS_ADDED), is(recipients));
    }

    @Test
    public void testAddResourceRecipientsAddedNullIsIgnored() {
        message.addResourceRecipientsAdded(null);
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_RECIPIENTS_ADDED));
    }

    @Test
    public void testAddResourceRecipientsRevokedPopulatesField() {
        String recipients = "ShareWith {read_only={users=[charlie]}}";
        message.addResourceRecipientsRevoked(recipients);
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_RECIPIENTS_REVOKED), is(recipients));
    }

    @Test
    public void testAddResourceRecipientsRevokedNullIsIgnored() {
        message.addResourceRecipientsRevoked(null);
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_RECIPIENTS_REVOKED));
    }

    @Test
    public void testAddResourceShareWithPopulatesField() {
        String shareWith = "ShareWith {read_write={users=[bob]}, general_access=read_only}";
        message.addResourceShareWith(shareWith);
        assertThat(message.getAsMap().get(AuditMessage.RESOURCE_SHARE_WITH), is(shareWith));
    }

    @Test
    public void testAddResourceShareWithNullIsIgnored() {
        message.addResourceShareWith(null);
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_SHARE_WITH));
    }

    @Test
    public void testResourceAccessGrantedMessageHasCorrectCategory() {
        AuditMessage msg = new AuditMessage(AuditCategory.RESOURCE_ACCESS_GRANTED, clusterServiceMock, null, null);
        msg.addResourceId("query-456");
        msg.addResourceType("saved_query");
        msg.addResourceAccessResult("granted");
        msg.addEffectiveUser("bob");

        Map<String, Object> fields = msg.getAsMap();
        assertThat(fields.get(AuditMessage.CATEGORY), is(AuditCategory.RESOURCE_ACCESS_GRANTED));
        assertThat(fields.get(AuditMessage.RESOURCE_ID), is("query-456"));
        assertThat(fields.get(AuditMessage.RESOURCE_TYPE), is("saved_query"));
        assertThat(fields.get(AuditMessage.RESOURCE_ACCESS_RESULT), is("granted"));
        assertThat(fields.get(AuditMessage.REQUEST_EFFECTIVE_USER), is("bob"));
    }

    @Test
    public void testResourceSharingChangedMessageHasCorrectCategory() {
        AuditMessage msg = new AuditMessage(AuditCategory.RESOURCE_SHARING_CHANGED, clusterServiceMock, null, null);
        msg.addResourceId("dashboard-789");
        msg.addResourceType("dashboard");
        msg.addResourceSharingAction("patch");
        msg.addResourceRecipientsAdded("added-info");
        msg.addResourceRecipientsRevoked("revoked-info");
        msg.addEffectiveUser("alice");

        Map<String, Object> fields = msg.getAsMap();
        assertThat(fields.get(AuditMessage.CATEGORY), is(AuditCategory.RESOURCE_SHARING_CHANGED));
        assertThat(fields.get(AuditMessage.RESOURCE_ID), is("dashboard-789"));
        assertThat(fields.get(AuditMessage.RESOURCE_SHARING_ACTION), is("patch"));
        assertThat(fields.get(AuditMessage.RESOURCE_RECIPIENTS_ADDED), is("added-info"));
        assertThat(fields.get(AuditMessage.RESOURCE_RECIPIENTS_REVOKED), is("revoked-info"));
        assertThat(fields.get(AuditMessage.REQUEST_EFFECTIVE_USER), is("alice"));
    }

    @Test
    public void testNewCategoriesParseFromStrings() {
        Set<AuditCategory> parsed = AuditCategory.parse(
            List.of("RESOURCE_ACCESS_GRANTED", "RESOURCE_ACCESS_DENIED", "RESOURCE_SHARING_CHANGED")
        );
        assertThat(parsed.size(), is(3));
        assertThat(parsed.contains(AuditCategory.RESOURCE_ACCESS_GRANTED), is(true));
        assertThat(parsed.contains(AuditCategory.RESOURCE_ACCESS_DENIED), is(true));
        assertThat(parsed.contains(AuditCategory.RESOURCE_SHARING_CHANGED), is(true));
    }

    @Test
    public void testNewCategoriesAreInAuthOnlySet() {
        assertThat(AuditCategory.AUTH_ONLY_CATEGORIES.contains(AuditCategory.RESOURCE_ACCESS_GRANTED), is(true));
        assertThat(AuditCategory.AUTH_ONLY_CATEGORIES.contains(AuditCategory.RESOURCE_ACCESS_DENIED), is(true));
        assertThat(AuditCategory.AUTH_ONLY_CATEGORIES.contains(AuditCategory.RESOURCE_SHARING_CHANGED), is(true));
    }

    @Test
    public void testNewCategoriesInDefaultDisabledRestList() {
        List<String> defaults = org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_REST_CATEGORIES_DEFAULT;
        assertThat(defaults.contains(AuditCategory.RESOURCE_ACCESS_GRANTED.toString()), is(true));
        assertThat(defaults.contains(AuditCategory.RESOURCE_ACCESS_DENIED.toString()), is(true));
        assertThat(defaults.contains(AuditCategory.RESOURCE_SHARING_CHANGED.toString()), is(true));
    }

    @Test
    public void testNewCategoriesInDefaultDisabledTransportList() {
        List<String> defaults =
            org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_TRANSPORT_CATEGORIES_DEFAULT;
        assertThat(defaults.contains(AuditCategory.RESOURCE_ACCESS_GRANTED.toString()), is(true));
        assertThat(defaults.contains(AuditCategory.RESOURCE_ACCESS_DENIED.toString()), is(true));
        assertThat(defaults.contains(AuditCategory.RESOURCE_SHARING_CHANGED.toString()), is(true));
    }

    @Test
    public void testResourceAccessDeniedMessageHasCorrectCategory() {
        AuditMessage msg = new AuditMessage(AuditCategory.RESOURCE_ACCESS_DENIED, clusterServiceMock, null, null);
        msg.addResourceId("dashboard-999");
        msg.addResourceType("dashboard");
        msg.addResourceAccessResult("denied");
        msg.addEffectiveUser("charlie");
        msg.addAction("plugins:dashboard/get");

        Map<String, Object> fields = msg.getAsMap();
        assertThat(fields.get(AuditMessage.CATEGORY), is(AuditCategory.RESOURCE_ACCESS_DENIED));
        assertThat(fields.get(AuditMessage.RESOURCE_ID), is("dashboard-999"));
        assertThat(fields.get(AuditMessage.RESOURCE_ACCESS_RESULT), is("denied"));
        assertThat(fields.get(AuditMessage.REQUEST_EFFECTIVE_USER), is("charlie"));
        assertThat(fields.get(AuditMessage.TRANSPORT_ACTION), is("plugins:dashboard/get"));
    }

    @Test
    public void testAllResourceFieldsPopulatedSimultaneously() {
        AuditMessage msg = new AuditMessage(AuditCategory.RESOURCE_SHARING_CHANGED, clusterServiceMock, null, null);
        msg.addResourceId("res-001");
        msg.addResourceType("saved_query");
        msg.addResourceIndex(".resource-sharing");
        msg.addResourceSharingAction("patch");
        msg.addResourceRecipientsAdded("added-users");
        msg.addResourceRecipientsRevoked("revoked-users");
        msg.addResourceShareWith("share-with-info");
        msg.addResourceAccessResult("granted");
        msg.addEffectiveUser("admin");

        Map<String, Object> fields = msg.getAsMap();
        assertThat(fields.get(AuditMessage.RESOURCE_ID), is("res-001"));
        assertThat(fields.get(AuditMessage.RESOURCE_TYPE), is("saved_query"));
        assertThat(fields.get(AuditMessage.RESOURCE_INDEX), is(".resource-sharing"));
        assertThat(fields.get(AuditMessage.RESOURCE_SHARING_ACTION), is("patch"));
        assertThat(fields.get(AuditMessage.RESOURCE_RECIPIENTS_ADDED), is("added-users"));
        assertThat(fields.get(AuditMessage.RESOURCE_RECIPIENTS_REVOKED), is("revoked-users"));
        assertThat(fields.get(AuditMessage.RESOURCE_SHARE_WITH), is("share-with-info"));
        assertThat(fields.get(AuditMessage.RESOURCE_ACCESS_RESULT), is("granted"));
        assertThat(fields.get(AuditMessage.REQUEST_EFFECTIVE_USER), is("admin"));
    }

    @Test
    public void testAddResourceAccessResultNullIsIgnored() {
        message.addResourceAccessResult(null);
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_ACCESS_RESULT));
    }

    @Test
    public void testAddResourceAccessResultEmptyIsIgnored() {
        message.addResourceAccessResult("");
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_ACCESS_RESULT));
    }

    @Test
    public void testAddResourceSharingActionNullIsIgnored() {
        message.addResourceSharingAction(null);
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_SHARING_ACTION));
    }

    @Test
    public void testAddResourceSharingActionEmptyIsIgnored() {
        message.addResourceSharingAction("");
        assertNull(message.getAsMap().get(AuditMessage.RESOURCE_SHARING_ACTION));
    }

    @Test
    public void testResourceFieldsAppearInJson() {
        AuditMessage msg = new AuditMessage(AuditCategory.RESOURCE_ACCESS_GRANTED, clusterServiceMock, null, null);
        msg.addResourceId("json-test-resource");
        msg.addResourceType("saved_query");
        msg.addResourceAccessResult("granted");

        String json = msg.toJson();
        assertThat(json, containsString("\"audit_resource_id\":\"json-test-resource\""));
        assertThat(json, containsString("\"audit_resource_type\":\"saved_query\""));
        assertThat(json, containsString("\"audit_resource_access_result\":\"granted\""));
    }

    // =====================================================================
    // audit_request_id — correlation field tests
    // =====================================================================

    @Test
    public void testAddRequestIdPopulatesField() {
        message.addRequestId("4bf92f3577b34da6a3ce929d0e0e4736");
        assertThat(message.getAsMap().get(AuditMessage.REQUEST_ID), is("4bf92f3577b34da6a3ce929d0e0e4736"));
    }

    @Test
    public void testAddRequestIdNullIsIgnored() {
        message.addRequestId(null);
        assertNull(message.getAsMap().get(AuditMessage.REQUEST_ID));
    }

    @Test
    public void testAddRequestIdEmptyStringIsIgnored() {
        // Empty string is rejected — only non-empty values are stored
        message.addRequestId("");
        assertNull(message.getAsMap().get(AuditMessage.REQUEST_ID));
    }

    @Test
    public void testAddRequestIdAppearsInJson() throws Exception {
        message.addRequestId("trace-abc-123");
        String json = message.toJson();
        assertThat(json, containsString("\"audit_request_id\":\"trace-abc-123\""));
    }

    // --- Tests for audit field enrichment methods ---

    @Test
    public void testAddUserRolesNull() {
        message.addUserRoles(null);
        assertNull(message.getAsMap().get(AuditMessage.USER_ROLES));
    }

    @Test
    public void testAddUserRolesEmpty() {
        message.addUserRoles(Collections.emptySet());
        assertNull(message.getAsMap().get(AuditMessage.USER_ROLES));
    }

    @Test
    public void testAddUserRolesDeterministicOrder() {
        // Roles should be sorted alphabetically regardless of insertion order
        java.util.Set<String> roles = new java.util.LinkedHashSet<>();
        roles.add("zebra_role");
        roles.add("admin");
        roles.add("data_engineer");

        message.addUserRoles(roles);
        Object result = message.getAsMap().get(AuditMessage.USER_ROLES);
        assertThat(result, is(List.of("admin", "data_engineer", "zebra_role")));
    }

    @Test
    public void testAddUserRolesSingleRole() {
        message.addUserRoles(java.util.Set.of("only_role"));
        Object result = message.getAsMap().get(AuditMessage.USER_ROLES);
        assertThat(result, is(List.of("only_role")));
    }

    @Test
    public void testAddAuthMethodNull() {
        message.addAuthMethod(null);
        assertNull(message.getAsMap().get(AuditMessage.AUTH_METHOD));
    }

    @Test
    public void testAddAuthMethodEmpty() {
        message.addAuthMethod("");
        assertNull(message.getAsMap().get(AuditMessage.AUTH_METHOD));
    }

    @Test
    public void testAddAuthMethodValid() {
        message.addAuthMethod("internal");
        assertThat(message.getAsMap().get(AuditMessage.AUTH_METHOD), is("internal"));
    }

    @Test
    public void testAddUserAgentNull() {
        message.addUserAgent(null);
        assertNull(message.getAsMap().get(AuditMessage.USER_AGENT));
    }

    @Test
    public void testAddUserAgentEmpty() {
        message.addUserAgent("");
        assertNull(message.getAsMap().get(AuditMessage.USER_AGENT));
    }

    @Test
    public void testAddUserAgentValid() {
        message.addUserAgent("curl/7.68.0");
        assertThat(message.getAsMap().get(AuditMessage.USER_AGENT), is("curl/7.68.0"));
    }

    @Test
    public void testAddUserAgentSpecialCharacters() {
        String complexAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0";
        message.addUserAgent(complexAgent);
        assertThat(message.getAsMap().get(AuditMessage.USER_AGENT), is(complexAgent));
    }

    @Test
    public void testUserAgentExtractionRespectsIgnoreHeaders() {
        // When filter excludes "User-Agent" (the actual header key from the request),
        // addRestRequestInfo should NOT extract it
        when(auditFilterMock.shouldExcludeHeader("User-Agent")).thenReturn(true);
        when(auditFilterMock.shouldLogRequestBody()).thenReturn(false);

        HttpRequest httpRequest = mock(HttpRequest.class);
        when(httpRequest.uri()).thenReturn("/_cluster/health");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[0]));
        Map<String, List<String>> headers = ImmutableMap.of("User-Agent", ImmutableList.of("curl/7.68.0"));
        when(httpRequest.getHeaders()).thenReturn(headers);

        RestRequest restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        SecurityRequest request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditFilterMock);
        assertNull(message.getAsMap().get(AuditMessage.USER_AGENT));
    }

    @Test
    public void testUserAgentExtractionWhenNotExcluded() {
        // When filter does NOT exclude "user-agent", it should be extracted
        when(auditFilterMock.shouldExcludeHeader("user-agent")).thenReturn(false);
        when(auditFilterMock.shouldExcludeHeader("User-Agent")).thenReturn(false);
        when(auditFilterMock.shouldLogRequestBody()).thenReturn(false);

        HttpRequest httpRequest = mock(HttpRequest.class);
        when(httpRequest.uri()).thenReturn("/_cluster/health");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[0]));
        Map<String, List<String>> headers = ImmutableMap.of("User-Agent", ImmutableList.of("opensearch-java/2.6.0"));
        when(httpRequest.getHeaders()).thenReturn(headers);

        RestRequest restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        SecurityRequest request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditFilterMock);
        assertThat(message.getAsMap().get(AuditMessage.USER_AGENT), is("opensearch-java/2.6.0"));
    }

    @Test
    public void testUserAgentExclusionUsesActualHeaderKey() {
        // Proves our code passes the actual header key ("User-Agent") to shouldExcludeHeader(),
        // NOT a hardcoded lowercase "user-agent". The mock returns true only for the exact
        // canonical casing — if our code still used the hardcoded lowercase, this test would FAIL.
        when(auditFilterMock.shouldExcludeHeader("User-Agent")).thenReturn(true);
        when(auditFilterMock.shouldExcludeHeader("user-agent")).thenReturn(false);
        when(auditFilterMock.shouldLogRequestBody()).thenReturn(false);

        HttpRequest httpRequest = mock(HttpRequest.class);
        when(httpRequest.uri()).thenReturn("/_cluster/health");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[0]));
        Map<String, List<String>> headers = ImmutableMap.of("User-Agent", ImmutableList.of("curl/7.68.0"));
        when(httpRequest.getHeaders()).thenReturn(headers);

        RestRequest restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        SecurityRequest request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditFilterMock);

        // Should be excluded because our code passes "User-Agent" (the actual key) to the filter
        assertNull("User-Agent should be excluded when filter excludes the actual header key",
            message.getAsMap().get(AuditMessage.USER_AGENT));
    }

    @Test
    public void testUserAgentExtractedWhenNotInIgnoreHeaders() {
        // When the filter does not exclude any form of user-agent, it should be extracted normally
        when(auditFilterMock.shouldExcludeHeader("User-Agent")).thenReturn(false);
        when(auditFilterMock.shouldExcludeHeader("user-agent")).thenReturn(false);
        when(auditFilterMock.shouldLogRequestBody()).thenReturn(false);

        HttpRequest httpRequest = mock(HttpRequest.class);
        when(httpRequest.uri()).thenReturn("/_cluster/health");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[0]));
        Map<String, List<String>> headers = ImmutableMap.of("User-Agent", ImmutableList.of("opensearch-py/2.4.0"));
        when(httpRequest.getHeaders()).thenReturn(headers);

        RestRequest restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        SecurityRequest request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditFilterMock);

        assertThat(message.getAsMap().get(AuditMessage.USER_AGENT), is("opensearch-py/2.4.0"));
    }
}
