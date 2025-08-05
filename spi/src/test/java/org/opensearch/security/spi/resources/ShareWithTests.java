/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.junit.Test;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.Recipients;
import org.opensearch.security.spi.resources.sharing.ShareWith;

import org.mockito.Mockito;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
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

        ShareWith shareWith = ShareWith.fromXContent(parser);

        MatcherAssert.assertThat(shareWith, notNullValue());
        Recipients readOnly = shareWith.atAccessLevel("read_only");
        MatcherAssert.assertThat(readOnly, notNullValue());

        Map<Recipient, Set<String>> recipients = readOnly.getRecipients();
        MatcherAssert.assertThat(recipients, notNullValue());
        MatcherAssert.assertThat(recipients.get(Recipient.USERS).size(), is(1));
        MatcherAssert.assertThat(recipients.get(Recipient.USERS), contains("user1"));
        MatcherAssert.assertThat(recipients.get(Recipient.ROLES).size(), is(0));
        MatcherAssert.assertThat(recipients.get(Recipient.BACKEND_ROLES).size(), is(0));
    }

    @Test
    public void testFromXContentWithEmptyInput() throws IOException {
        String emptyJson = "{}";
        XContentParser parser = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, null, emptyJson);

        ShareWith result = ShareWith.fromXContent(parser);

        MatcherAssert.assertThat(result, notNullValue());
        MatcherAssert.assertThat(result.isPrivate(), is(true));
        MatcherAssert.assertThat(result.isPublic(), is(false));
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

        ShareWith shareWith = ShareWith.fromXContent(parser);

        MatcherAssert.assertThat(shareWith, notNullValue());

        Recipients defaultAccessLevel = shareWith.atAccessLevel("default");

        Recipients readOnly = shareWith.atAccessLevel("read-only");

        MatcherAssert.assertThat(defaultAccessLevel, notNullValue());
        MatcherAssert.assertThat(readOnly, notNullValue());

        MatcherAssert.assertThat(defaultAccessLevel.getRecipientsByType(Recipient.USERS).size(), is(2));
        MatcherAssert.assertThat(defaultAccessLevel.getRecipientsByType(Recipient.ROLES).size(), is(1));
        MatcherAssert.assertThat(defaultAccessLevel.getRecipientsByType(Recipient.BACKEND_ROLES).size(), is(1));

        MatcherAssert.assertThat(readOnly.getRecipientsByType(Recipient.USERS).size(), is(1));
        MatcherAssert.assertThat(readOnly.getRecipientsByType(Recipient.ROLES).size(), is(1));
        MatcherAssert.assertThat(readOnly.getRecipientsByType(Recipient.BACKEND_ROLES).size(), is(1));
    }

    @Test
    public void testFromXContentWithUnexpectedEndOfInput() throws IOException {
        XContentParser mockParser = mock(XContentParser.class);
        when(mockParser.currentToken()).thenReturn(XContentParser.Token.START_OBJECT);
        when(mockParser.nextToken()).thenReturn(XContentParser.Token.END_OBJECT, (XContentParser.Token) null);

        ShareWith result = ShareWith.fromXContent(mockParser);

        MatcherAssert.assertThat(result, notNullValue());
        MatcherAssert.assertThat(result.isPrivate(), is(true));
        MatcherAssert.assertThat(result.isPublic(), is(false));
    }

    @Test
    public void testToXContentBuildsCorrectly() throws IOException {
        Recipients actionGroup = new Recipients(Map.of(Recipient.USERS, Set.of("bleh")));

        ShareWith shareWith = new ShareWith(Map.of("actionGroup1", actionGroup));

        XContentBuilder builder = JsonXContent.contentBuilder();

        shareWith.toXContent(builder, ToXContent.EMPTY_PARAMS);

        String result = builder.toString();

        String expected = "{\"actionGroup1\":{\"users\":[\"bleh\"]}}";

        MatcherAssert.assertThat(expected.length(), equalTo(result.length()));
        MatcherAssert.assertThat(expected, equalTo(result));
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

        ShareWith shareWith = ShareWith.fromXContent(parser);

        MatcherAssert.assertThat(shareWith.isPrivate(), is(true));
        MatcherAssert.assertThat(shareWith.isPublic(), is(false));
    }

    @Test
    public void test_writeSharedWithScopesToStream() throws IOException {
        StreamOutput mockStreamOutput = Mockito.mock(StreamOutput.class);

        Map<String, Recipients> map = Map.of("default", new Recipients(Map.of()));

        ShareWith shareWith = new ShareWith(map);

        shareWith.writeTo(mockStreamOutput);

        verify(mockStreamOutput, times(1)).writeMap(eq(map), any(), any());
    }
}
