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
import java.util.HashSet;
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
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;

import org.mockito.Mockito;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
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
        Set<SharedWithActionGroup> sharedWithActionGroups = shareWith.getSharedWithActionGroups();
        MatcherAssert.assertThat(sharedWithActionGroups, notNullValue());
        MatcherAssert.assertThat(1, equalTo(sharedWithActionGroups.size()));

        SharedWithActionGroup actionGroup = sharedWithActionGroups.iterator().next();
        MatcherAssert.assertThat("read_only", equalTo(actionGroup.getActionGroup()));

        SharedWithActionGroup.ActionGroupRecipients actionGroupRecipients = actionGroup.getSharedWithPerActionGroup();
        MatcherAssert.assertThat(actionGroupRecipients, notNullValue());
        Map<Recipient, Set<String>> recipients = actionGroupRecipients.getRecipients();
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
        MatcherAssert.assertThat(result.getSharedWithActionGroups(), is(empty()));
    }

    @Test
    public void testFromXContentWithStartObject() throws IOException {
        XContentParser parser;
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            builder.startObject()
                .startObject(ResourceAccessActionGroups.PLACE_HOLDER)
                .array("users", "user1", "user2")
                .array("roles", "role1")
                .array("backend_roles", "backend_role1")
                .endObject()
                .startObject("random-action-group")
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
        Set<SharedWithActionGroup> actionGroups = shareWith.getSharedWithActionGroups();
        MatcherAssert.assertThat(actionGroups.size(), equalTo(2));

        for (SharedWithActionGroup actionGroup : actionGroups) {
            SharedWithActionGroup.ActionGroupRecipients perScope = actionGroup.getSharedWithPerActionGroup();
            Map<Recipient, Set<String>> recipients = perScope.getRecipients();
            if (actionGroup.getActionGroup().equals(ResourceAccessActionGroups.PLACE_HOLDER)) {
                MatcherAssert.assertThat(recipients.get(Recipient.USERS).size(), is(2));
                MatcherAssert.assertThat(recipients.get(Recipient.ROLES).size(), is(1));
                MatcherAssert.assertThat(recipients.get(Recipient.BACKEND_ROLES).size(), is(1));
            } else if (actionGroup.getActionGroup().equals("random-action-group")) {
                MatcherAssert.assertThat(recipients.get(Recipient.USERS).size(), is(1));
                MatcherAssert.assertThat(recipients.get(Recipient.ROLES).size(), is(1));
                MatcherAssert.assertThat(recipients.get(Recipient.BACKEND_ROLES).size(), is(1));
            }
        }
    }

    @Test
    public void testFromXContentWithUnexpectedEndOfInput() throws IOException {
        XContentParser mockParser = mock(XContentParser.class);
        when(mockParser.currentToken()).thenReturn(XContentParser.Token.START_OBJECT);
        when(mockParser.nextToken()).thenReturn(XContentParser.Token.END_OBJECT, (XContentParser.Token) null);

        ShareWith result = ShareWith.fromXContent(mockParser);

        MatcherAssert.assertThat(result, notNullValue());
        MatcherAssert.assertThat(result.getSharedWithActionGroups(), is(empty()));
    }

    @Test
    public void testToXContentBuildsCorrectly() throws IOException {
        SharedWithActionGroup actionGroup = new SharedWithActionGroup(
            "actionGroup1",
            new SharedWithActionGroup.ActionGroupRecipients(Map.of(Recipient.USERS, Set.of("bleh")))
        );

        Set<SharedWithActionGroup> actionGroups = new HashSet<>();
        actionGroups.add(actionGroup);

        ShareWith shareWith = new ShareWith(actionGroups);

        XContentBuilder builder = JsonXContent.contentBuilder();

        shareWith.toXContent(builder, ToXContent.EMPTY_PARAMS);

        String result = builder.toString();

        String expected = "{\"actionGroup1\":{\"users\":[\"bleh\"]}}";

        MatcherAssert.assertThat(expected.length(), equalTo(result.length()));
        MatcherAssert.assertThat(expected, equalTo(result));
    }

    @Test
    public void testWriteToWithEmptySet() throws IOException {
        Set<SharedWithActionGroup> emptySet = Collections.emptySet();
        ShareWith shareWith = new ShareWith(emptySet);
        StreamOutput mockOutput = Mockito.mock(StreamOutput.class);

        shareWith.writeTo(mockOutput);

        verify(mockOutput).writeCollection(emptySet);
    }

    @Test
    public void testWriteToWithIOException() throws IOException {
        Set<SharedWithActionGroup> set = new HashSet<>();
        set.add(new SharedWithActionGroup("test", new SharedWithActionGroup.ActionGroupRecipients(Map.of())));
        ShareWith shareWith = new ShareWith(set);
        StreamOutput mockOutput = Mockito.mock(StreamOutput.class);

        doThrow(new IOException("Simulated IO exception")).when(mockOutput).writeCollection(set);

        assertThrows(IOException.class, () -> shareWith.writeTo(mockOutput));
    }

    @Test
    public void testWriteToWithLargeSet() throws IOException {
        Set<SharedWithActionGroup> largeSet = new HashSet<>();
        for (int i = 0; i < 10000; i++) {
            largeSet.add(new SharedWithActionGroup("actionGroup" + i, new SharedWithActionGroup.ActionGroupRecipients(Map.of())));
        }
        ShareWith shareWith = new ShareWith(largeSet);
        StreamOutput mockOutput = Mockito.mock(StreamOutput.class);

        shareWith.writeTo(mockOutput);

        verify(mockOutput).writeCollection(largeSet);
    }

    @Test
    public void test_fromXContent_emptyObject() throws IOException {
        XContentParser parser;
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            builder.startObject().endObject();
            parser = XContentType.JSON.xContent().createParser(null, null, builder.toString());
        }

        ShareWith shareWith = ShareWith.fromXContent(parser);

        MatcherAssert.assertThat(shareWith.getSharedWithActionGroups(), is(empty()));
    }

    @Test
    public void test_writeSharedWithScopesToStream() throws IOException {
        StreamOutput mockStreamOutput = Mockito.mock(StreamOutput.class);

        Set<SharedWithActionGroup> sharedWithActionGroups = new HashSet<>();
        sharedWithActionGroups.add(
            new SharedWithActionGroup(ResourceAccessActionGroups.PLACE_HOLDER, new SharedWithActionGroup.ActionGroupRecipients(Map.of()))
        );

        ShareWith shareWith = new ShareWith(sharedWithActionGroups);

        shareWith.writeTo(mockStreamOutput);

        verify(mockStreamOutput, times(1)).writeCollection(eq(sharedWithActionGroups));
    }
}

enum DefaultRecipient {
    USERS("users"),
    ROLES("roles"),
    BACKEND_ROLES("backend_roles");

    private final String name;

    DefaultRecipient(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
