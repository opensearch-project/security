/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.sharing;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for ShareWith class
 *
 * @opensearch.experimental
 */
public class ShareWithTests {

    @Test
    public void testFromXContentWhenCurrentTokenIsNotStartObject() throws IOException {
        String json = "{\"read_only\": {\"users\": [\"user1\"], \"roles\": [], \"backend_roles\": []}}";
        XContentParser parser = JsonXContent.jsonXContent.createParser(null, null, json);

        parser.nextToken();

        ShareWith shareWith = ShareWith.fromXContent(parser, Set.of("read_only"));

        assertThat(shareWith, notNullValue());
        Recipients readOnly = shareWith.atAccessLevel("read_only");
        assertThat(readOnly, notNullValue());

        Map<Recipient, Set<String>> recipients = readOnly.getRecipients();
        assertThat(recipients, notNullValue());
        assertThat(recipients.get(Recipient.USERS).size(), is(1));
        assertThat(recipients.get(Recipient.USERS), contains("user1"));
        assertThat(recipients.get(Recipient.ROLES).size(), is(0));
        assertThat(recipients.get(Recipient.BACKEND_ROLES).size(), is(0));
    }

    @Test
    public void testFromXContentWithEmptyInput() throws IOException {
        String emptyJson = "{}";
        XContentParser parser = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, null, emptyJson);

        ShareWith result = ShareWith.fromXContent(parser, Set.of());

        assertThat(result, notNullValue());
        assertThat(result.isPrivate(), is(true));
        assertThat(result.isPublic(), is(false));
    }

    @Test
    public void testFromXContentWithStartObject() throws IOException {
        XContentParser parser;
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            builder.startObject()
                .startObject("default")
                .array("users", "user1", "user2")
                .array("roles", "role1")
                .array("backend_roles", "backend_role1")
                .endObject()
                .startObject("read-only")
                .array("users", "*")
                .array("roles", "*")
                .array("backend_roles", "*")
                .endObject()
                .endObject();

            parser = JsonXContent.jsonXContent.createParser(null, null, builder.toString());
        }

        parser.nextToken();

        ShareWith shareWith = ShareWith.fromXContent(parser, Set.of("read_only", "default"));

        assertThat(shareWith, notNullValue());

        Recipients defaultAccessLevel = shareWith.atAccessLevel("default");

        Recipients readOnly = shareWith.atAccessLevel("read-only");

        assertThat(defaultAccessLevel, notNullValue());
        assertThat(readOnly, notNullValue());

        assertThat(defaultAccessLevel.getRecipientsByType(Recipient.USERS).size(), is(2));
        assertThat(defaultAccessLevel.getRecipientsByType(Recipient.ROLES).size(), is(1));
        assertThat(defaultAccessLevel.getRecipientsByType(Recipient.BACKEND_ROLES).size(), is(1));

        assertThat(readOnly.getRecipientsByType(Recipient.USERS).size(), is(1));
        assertThat(readOnly.getRecipientsByType(Recipient.ROLES).size(), is(1));
        assertThat(readOnly.getRecipientsByType(Recipient.BACKEND_ROLES).size(), is(1));
    }

    @Test
    public void testFromXContentWithUnexpectedEndOfInput() throws IOException {
        XContentParser mockParser = mock(XContentParser.class);
        when(mockParser.currentToken()).thenReturn(XContentParser.Token.START_OBJECT);
        when(mockParser.nextToken()).thenReturn(XContentParser.Token.END_OBJECT, (XContentParser.Token) null);

        ShareWith result = ShareWith.fromXContent(mockParser, Set.of());

        assertThat(result, notNullValue());
        assertThat(result.isPrivate(), is(true));
        assertThat(result.isPublic(), is(false));
    }

    @Test
    public void testToXContentBuildsCorrectly() throws IOException {
        Recipients actionGroup = new Recipients(Map.of(Recipient.USERS, Set.of("bleh")));

        ShareWith shareWith = new ShareWith(Map.of("actionGroup1", actionGroup));

        XContentBuilder builder = JsonXContent.contentBuilder();

        shareWith.toXContent(builder, ToXContent.EMPTY_PARAMS);

        String result = builder.toString();

        String expected = "{\"actionGroup1\":{\"users\":[\"bleh\"]}}";

        assertThat(expected.length(), equalTo(result.length()));
        assertThat(expected, equalTo(result));
    }

    @Test
    public void testWriteToWithEmptySet() throws IOException {
        Map<String, Recipients> emptyMap = Collections.emptyMap();
        ShareWith shareWith = new ShareWith(emptyMap);
        StreamOutput mockOutput = Mockito.mock(StreamOutput.class);

        shareWith.writeTo(mockOutput);

        verify(mockOutput).writeMap(eq(emptyMap), any(), any());
    }

    @Test
    public void testWriteToWithIOException() throws IOException {
        Recipients recipients = new Recipients(Map.of());
        Map<String, Recipients> map = Map.of("test", recipients);
        ShareWith shareWith = new ShareWith(map);
        StreamOutput mockOutput = Mockito.mock(StreamOutput.class);

        doThrow(new IOException("Simulated IO exception")).when(mockOutput).writeMap(eq(map), any(), any());

        assertThrows(IOException.class, () -> shareWith.writeTo(mockOutput));
    }

    @Test
    public void testWriteToWithLargeSet() throws IOException {
        Map<String, Recipients> largeMap = new HashMap<>();
        for (int i = 0; i < 10; i++) {
            largeMap.put("actionGroup" + i, new Recipients(Map.of()));
        }
        ShareWith shareWith = new ShareWith(largeMap);
        StreamOutput mockOutput = Mockito.mock(StreamOutput.class);

        shareWith.writeTo(mockOutput);

        verify(mockOutput).writeMap(eq(largeMap), any(), any());
    }

    @Test
    public void test_fromXContent_emptyObject() throws IOException {
        XContentParser parser;
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            builder.startObject().endObject();
            parser = XContentType.JSON.xContent().createParser(null, null, builder.toString());
        }

        ShareWith shareWith = ShareWith.fromXContent(parser, Set.of());

        assertThat(shareWith.isPrivate(), is(true));
        assertThat(shareWith.isPublic(), is(false));
    }

    @Test
    public void test_writeSharedWithScopesToStream() throws IOException {
        StreamOutput mockStreamOutput = Mockito.mock(StreamOutput.class);

        Map<String, Recipients> map = Map.of("default", new Recipients(Map.of()));

        ShareWith shareWith = new ShareWith(map);

        shareWith.writeTo(mockStreamOutput);

        verify(mockStreamOutput, times(1)).writeMap(eq(map), any(), any());
    }

    @Test
    public void testAdd_NewAndMerge() {
        // existing level
        Recipients orig = mock(Recipients.class);
        Map<String, Recipients> baseMap = new HashMap<>();
        baseMap.put("read", orig);
        ShareWith base = new ShareWith(baseMap);
        // patch for same level and a new level
        Recipients patchRec = mock(Recipients.class);
        Map<String, Recipients> patchMap = new HashMap<>();
        patchMap.put("read", patchRec);
        patchMap.put("write", patchRec);
        ShareWith patchSw = new ShareWith(patchMap);

        ShareWith result = base.add(patchSw);
        // existing level merged
        verify(orig, times(1)).share(patchRec);
        // new level added
        assertThat(result.atAccessLevel("write"), equalTo(patchRec));
    }

    @Test
    public void testRevoke_ExistingAndNoop() {
        Recipients orig = mock(Recipients.class);
        Map<String, Recipients> baseMap = new HashMap<>();
        baseMap.put("read", orig);
        ShareWith base = new ShareWith(baseMap);
        Recipients revokeRec = mock(Recipients.class);
        Map<String, Recipients> revokeMap = new HashMap<>();
        revokeMap.put("read", revokeRec);
        revokeMap.put("write", revokeRec);
        ShareWith revokeSw = new ShareWith(revokeMap);

        ShareWith result = base.revoke(revokeSw);
        // revoke called on existing
        verify(orig, times(1)).revoke(revokeRec);
        // non-existing level noop
        assertThat(result.atAccessLevel("write"), nullValue());
    }

    @Test
    public void testRevoke_NonExisting() {
        ShareWith base = new ShareWith(new HashMap<>());
        Recipients revokeRec = mock(Recipients.class);
        Map<String, Recipients> revokeMap = new HashMap<>();
        revokeMap.put("read", revokeRec);
        revokeMap.put("write", revokeRec);
        ShareWith revokeSw = new ShareWith(revokeMap);

        assertThat(base.getSharingInfo().size(), is(0));

        ShareWith result = base.revoke(revokeSw);
        // revoke called on existing
        assertThat("Revoke on empty base should return the same object", result, sameInstance(base));
        // assert no levels were added or removed
        assertThat(result.getSharingInfo().size(), is(0));
    }

    @Test
    public void testChainedAddThenRevoke() {
        ShareWith base = new ShareWith(new HashMap<>());
        Recipients addRec = mock(Recipients.class);
        ShareWith added = base.add(new ShareWith(Map.of("read", addRec)));
        // verify added
        verify(addRec, never()).share(any()); // no existing, so no share call
        // now revoke
        Recipients revokeRec = mock(Recipients.class);
        ShareWith revoked = added.revoke(new ShareWith(Map.of("read", revokeRec)));
        verify(addRec, times(1)).revoke(revokeRec);
    }
}
