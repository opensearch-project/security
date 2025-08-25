/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.io.IOException;

import org.hamcrest.MatcherAssert;
import org.junit.Test;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.spi.resources.sharing.CreatedBy;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for CreatedBy class
 *
 * @opensearch.experimental
 */
public class CreatedByTests {

    @Test
    public void testCreatedByConstructorWithValidUser() {
        String expectedUser = "testUser";
        CreatedBy createdBy = new CreatedBy(expectedUser);

        MatcherAssert.assertThat(expectedUser, is(equalTo(createdBy.getUsername())));
    }

    @Test
    public void testCreatedByConstructorWithValidUserAndTenant() {
        String expectedUser = "testUser";
        String expectedTenant = "customTenant";
        CreatedBy createdBy = new CreatedBy(expectedUser, expectedTenant);

        MatcherAssert.assertThat(expectedUser, is(equalTo(createdBy.getUsername())));
        MatcherAssert.assertThat(expectedTenant, is(equalTo(createdBy.getTenant())));
    }

    @Test
    public void testCreatedByFromStreamInput() throws IOException {
        String expectedUser = "testUser";

        try (BytesStreamOutput out = new BytesStreamOutput()) {
            out.writeString(expectedUser);

            StreamInput in = out.bytes().streamInput();

            CreatedBy createdBy = new CreatedBy(in);

            MatcherAssert.assertThat(expectedUser, is(equalTo(createdBy.getUsername())));
        }
    }

    @Test
    public void testCreatedByWithEmptyStreamInput() throws IOException {

        try (StreamInput mockStreamInput = mock(StreamInput.class)) {
            when(mockStreamInput.readString()).thenThrow(new IOException("EOF"));

            assertThrows(IOException.class, () -> new CreatedBy(mockStreamInput));
        }
    }

    @Test
    public void testCreatedByWithEmptyUser() {

        CreatedBy createdBy = new CreatedBy("");
        MatcherAssert.assertThat("", equalTo(createdBy.getUsername()));
    }

    @Test
    public void testCreatedByWithIOException() throws IOException {

        try (StreamInput mockStreamInput = mock(StreamInput.class)) {
            when(mockStreamInput.readString()).thenThrow(new IOException("Test IOException"));

            assertThrows(IOException.class, () -> new CreatedBy(mockStreamInput));
        }
    }

    @Test
    public void testCreatedByWithLongUsername() {
        String longUsername = "a".repeat(10000);
        CreatedBy createdBy = new CreatedBy(longUsername);
        MatcherAssert.assertThat(longUsername, equalTo(createdBy.getUsername()));
    }

    @Test
    public void testCreatedByWithUnicodeCharacters() {
        String unicodeUsername = "用户こんにちは";
        CreatedBy createdBy = new CreatedBy(unicodeUsername);
        MatcherAssert.assertThat(unicodeUsername, equalTo(createdBy.getUsername()));
    }

    @Test
    public void testFromXContentThrowsExceptionWhenUserFieldIsMissing() throws IOException {
        String emptyJson = "{}";
        IllegalArgumentException exception;
        try (XContentParser parser = JsonXContent.jsonXContent.createParser(null, null, emptyJson)) {

            exception = assertThrows(IllegalArgumentException.class, () -> CreatedBy.fromXContent(parser));
        }

        MatcherAssert.assertThat("created_by cannot be empty", equalTo(exception.getMessage()));
    }

    @Test
    public void testFromXContentWithEmptyInput() throws IOException {
        String emptyJson = "{}";
        try (XContentParser parser = JsonXContent.jsonXContent.createParser(null, null, emptyJson)) {

            assertThrows(IllegalArgumentException.class, () -> CreatedBy.fromXContent(parser));
        }
    }

    @Test
    public void testFromXContentWithExtraFields() throws IOException {
        String jsonWithExtraFields = "{\"user\": \"testUser\", \"extraField\": \"value\"}";
        XContentParser parser = JsonXContent.jsonXContent.createParser(null, null, jsonWithExtraFields);

        assertThrows(IllegalArgumentException.class, () -> CreatedBy.fromXContent(parser));
    }

    @Test
    public void testFromXContentWithIncorrectFieldType() throws IOException {
        String jsonWithIncorrectType = "{\"user\": 12345}";
        try (XContentParser parser = JsonXContent.jsonXContent.createParser(null, null, jsonWithIncorrectType)) {

            assertThrows(IllegalArgumentException.class, () -> CreatedBy.fromXContent(parser));
        }
    }

    @Test
    public void testFromXContentWithEmptyUser() throws IOException {
        String emptyJson = "{\"user\": \"\" }";
        CreatedBy createdBy;
        try (XContentParser parser = JsonXContent.jsonXContent.createParser(null, null, emptyJson)) {
            parser.nextToken();

            createdBy = CreatedBy.fromXContent(parser);
        }

        MatcherAssert.assertThat("", equalTo(createdBy.getUsername()));
    }

    @Test
    public void testFromXContentWithNullUserValue() throws IOException {
        String jsonWithNullUser = "{\"user\": null}";
        try (XContentParser parser = JsonXContent.jsonXContent.createParser(null, null, jsonWithNullUser)) {

            assertThrows(IllegalArgumentException.class, () -> CreatedBy.fromXContent(parser));
        }
    }

    @Test
    public void testFromXContentWithValidUser() throws IOException {
        String json = "{\"user\":\"testUser\"}";
        XContentParser parser = JsonXContent.jsonXContent.createParser(null, null, json);

        CreatedBy createdBy = CreatedBy.fromXContent(parser);

        MatcherAssert.assertThat(createdBy, notNullValue());
        MatcherAssert.assertThat("testUser", equalTo(createdBy.getUsername()));
    }

    @Test
    public void testGetCreatorReturnsCorrectValue() {
        String expectedUser = "testUser";
        CreatedBy createdBy = new CreatedBy(expectedUser);

        String actualUser = createdBy.getUsername();

        MatcherAssert.assertThat(expectedUser, equalTo(actualUser));
    }

    @Test
    public void testGetWriteableNameReturnsCorrectString() {
        CreatedBy createdBy = new CreatedBy("testUser");
        MatcherAssert.assertThat("created_by", equalTo(createdBy.getWriteableName()));
    }

    @Test
    public void testToStringWithEmptyUser() {
        CreatedBy createdBy = new CreatedBy("");
        String result = createdBy.toString();
        MatcherAssert.assertThat("CreatedBy {user=''}", equalTo(result));
    }

    @Test
    public void testToStringWithNullUser() {
        CreatedBy createdBy = new CreatedBy((String) null);
        String result = createdBy.toString();
        MatcherAssert.assertThat("CreatedBy {user='null'}", equalTo(result));
    }

    @Test
    public void testToStringWithLongUserName() {

        String longUserName = "a".repeat(1000);
        CreatedBy createdBy = new CreatedBy(longUserName);
        String result = createdBy.toString();
        MatcherAssert.assertThat(result.startsWith("CreatedBy {user='"), is(true));
        MatcherAssert.assertThat(result.endsWith("'}"), is(true));
        MatcherAssert.assertThat(1019, equalTo(result.length()));
    }

    @Test
    public void testToXContentWithEmptyUser() throws IOException {
        CreatedBy createdBy = new CreatedBy("");
        XContentBuilder builder = JsonXContent.contentBuilder();

        createdBy.toXContent(builder, null);
        String result = builder.toString();
        MatcherAssert.assertThat("{\"user\":\"\"}", equalTo(result));
    }

    @Test
    public void testWriteToWithExceptionInStreamOutput() throws IOException {
        CreatedBy createdBy = new CreatedBy("user1");
        try (StreamOutput failingOutput = new StreamOutput() {
            @Override
            public void writeByte(byte b) throws IOException {
                throw new IOException("Simulated IO exception");
            }

            @Override
            public void writeBytes(byte[] b, int offset, int length) throws IOException {
                throw new IOException("Simulated IO exception");
            }

            @Override
            public void flush() throws IOException {

            }

            @Override
            public void close() throws IOException {

            }

            @Override
            public void reset() throws IOException {

            }
        }) {

            assertThrows(IOException.class, () -> createdBy.writeTo(failingOutput));
        }
    }

    @Test
    public void testWriteToWithLongUserName() throws IOException {
        String longUserName = "a".repeat(65536);
        CreatedBy createdBy = new CreatedBy(longUserName);
        BytesStreamOutput out = new BytesStreamOutput();
        createdBy.writeTo(out);
        MatcherAssert.assertThat(out.size(), greaterThan(65536));
    }

    @Test
    public void test_createdByToStringReturnsCorrectFormat() {
        String testUser = "testUser";
        CreatedBy createdBy = new CreatedBy(testUser);

        String expected = "CreatedBy {user='" + testUser + "'}";
        String actual = createdBy.toString();

        MatcherAssert.assertThat(expected, equalTo(actual));
    }

    @Test
    public void test_toXContent_serializesCorrectly() throws IOException {
        String expectedUser = "testUser";
        CreatedBy createdBy = new CreatedBy(expectedUser);
        XContentBuilder builder = XContentFactory.jsonBuilder();

        createdBy.toXContent(builder, null);

        String expectedJson = "{\"user\":\"testUser\"}";
        MatcherAssert.assertThat(expectedJson, equalTo(builder.toString()));
    }

    @Test
    public void test_writeTo_writesUserCorrectly() throws IOException {
        String expectedUser = "testUser";
        CreatedBy createdBy = new CreatedBy(expectedUser);

        BytesStreamOutput out = new BytesStreamOutput();
        createdBy.writeTo(out);

        StreamInput in = out.bytes().streamInput();
        String actualUser = in.readString();

        MatcherAssert.assertThat(expectedUser, equalTo(actualUser));
    }

}
