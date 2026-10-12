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

package org.opensearch.security.dlic.rest.api.pagination;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.SecurityConfiguration;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.util.FakeRestRequest;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class PaginationHelperTest {

    // ---------------------------------------------------------------------
    // isRequested / consumeParameters
    // ---------------------------------------------------------------------

    @Test
    public void isRequested_returnsFalseWhenNoParams() {
        final var request = FakeRestRequest.builder().withParams(Map.of()).build();
        assertThat(PaginationHelper.isRequested(request), is(false));
    }

    @Test
    public void isRequested_returnsTrueForAnyPaginationParam() {
        assertThat(PaginationHelper.isRequested(withParams(Map.of("size", "5"))), is(true));
        assertThat(PaginationHelper.isRequested(withParams(Map.of("sort", "asc"))), is(true));
        assertThat(PaginationHelper.isRequested(withParams(Map.of("next_token", "AAAA"))), is(true));
    }

    // ---------------------------------------------------------------------
    // parseAndValidate – rejects invalid inputs with 400
    // ---------------------------------------------------------------------

    @Test
    public void parseAndValidate_rejectsUnknownSort() {
        final var request = withParams(Map.of("sort", "sideways"));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAndValidate_rejectsNonIntegerSize() {
        final var request = withParams(Map.of("size", "not-a-number"));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAndValidate_rejectsSizeBelowRange() {
        final var request = withParams(Map.of("size", "0"));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAndValidate_rejectsSizeAboveMax() {
        final var request = withParams(Map.of("size", String.valueOf(PaginationHelper.MAX_PAGE_SIZE + 1)));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAndValidate_rejectsMalformedBase64Token() {
        final var request = withParams(Map.of("next_token", "@@@not-base64@@@"));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAndValidate_rejectsNonJsonToken() {
        final String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString("not json".getBytes(StandardCharsets.UTF_8));
        final var request = withParams(Map.of("next_token", tampered));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAndValidate_rejectsTokenIssuedForDifferentEndpoint() {
        final String cursor = PaginationHelper.encodeCursor(CType.ACTIONGROUPS, PaginationHelper.SORT_ASC, "ag_5");
        final var request = withParams(Map.of("next_token", cursor));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAndValidate_rejectsTokenIssuedForDifferentSort() {
        final String cursor = PaginationHelper.encodeCursor(CType.ROLES, PaginationHelper.SORT_ASC, "role_5");
        final var request = withParams(Map.of("next_token", cursor, "sort", PaginationHelper.SORT_DESC));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAndValidate_rejectsCursorWithMismatchedVersion() {
        final String tampered = tamperCursor(cursor -> cursor.replace("\"v\":1", "\"v\":999"));
        final var request = withParams(Map.of("next_token", tampered));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAndValidate_rejectsCursorPayloadThatIsValidJsonButNotAnObject() {
        // A syntactically-valid JSON payload of the wrong shape (an array, a number, a string,
        // etc.) must be rejected — not misinterpreted or NPE'd on missing fields.
        for (final String rawPayload : List.of("[1,2,3]", "\"just a string\"", "42", "null", "true")) {
            final String token = Base64.getUrlEncoder().withoutPadding().encodeToString(rawPayload.getBytes(StandardCharsets.UTF_8));
            final var result = PaginationHelper.parseAndValidate(withParams(Map.of("next_token", token)), CType.ROLES);
            assertThat("Payload [" + rawPayload + "] should be rejected", result.isValid(), is(false));
            assertThat(result.status(), is(RestStatus.BAD_REQUEST));
        }
    }

    @Test
    public void parseAndValidate_rejectsCursorMissingRequiredField() {
        // Drop each of the four required fields in turn and verify each variant is rejected.
        final Map<String, String> validPayload = Map.of("v", "1", "c", "roles", "s", "asc", "n", "role_a");
        for (final String toDrop : validPayload.keySet()) {
            final var payload = new java.util.LinkedHashMap<>(validPayload);
            payload.remove(toDrop);
            final String json = "{" + String.join(",", payload.entrySet().stream().map(e -> {
                // Keep "v" numeric, other fields string
                final String v = "v".equals(e.getKey()) ? e.getValue() : "\"" + e.getValue() + "\"";
                return "\"" + e.getKey() + "\":" + v;
            }).toList()) + "}";
            final String token = Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
            final var result = PaginationHelper.parseAndValidate(withParams(Map.of("next_token", token)), CType.ROLES);
            assertThat("Cursor missing field [" + toDrop + "] should be rejected", result.isValid(), is(false));
            assertThat(result.status(), is(RestStatus.BAD_REQUEST));
        }
    }

    @Test
    public void parseAndValidate_rejectsCursorWithWrongFieldTypes() {
        // Version-as-string, ctype-as-int, sort-as-array, name-as-null — each should be rejected
        // rather than accepted with a coerced value or crashed with an NPE.
        final List<String> badJsonPayloads = List.of(
            "{\"v\":\"1\",\"c\":\"roles\",\"s\":\"asc\",\"n\":\"role_a\"}", // v as string
            "{\"v\":1,\"c\":123,\"s\":\"asc\",\"n\":\"role_a\"}", // c as int
            "{\"v\":1,\"c\":\"roles\",\"s\":[\"asc\"],\"n\":\"role_a\"}", // s as array
            "{\"v\":1,\"c\":\"roles\",\"s\":\"asc\",\"n\":null}" // n as null
        );
        for (final String json : badJsonPayloads) {
            final String token = Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
            final var result = PaginationHelper.parseAndValidate(withParams(Map.of("next_token", token)), CType.ROLES);
            assertThat("Cursor with wrong types [" + json + "] should be rejected", result.isValid(), is(false));
            assertThat(result.status(), is(RestStatus.BAD_REQUEST));
        }
    }

    @Test
    public void parseAndValidate_acceptsMinimalValidRequest() throws IOException {
        final var request = withParams(Map.of("size", "10"));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(true));
        result.valid(params -> {
            assertThat(params.size(), is(10));
            assertThat(params.sort(), is(PaginationHelper.SORT_ASC));
            assertThat(params.lastName(), is(nullValue()));
        });
    }

    @Test
    public void encodeCursor_producesUrlSafeBase64() {
        // Force a payload that would use every non-alphanumeric byte in standard Base64 output
        // ('+' and '/'). URL-safe encoding must instead use '-' and '_' and drop '=' padding, so
        // the emitted cursor can be dropped directly into a query string without further encoding.
        final String cursor = PaginationHelper.encodeCursor(CType.ROLES, PaginationHelper.SORT_ASC, "\uFFFF\uFEFF\u00FF\u007F\u001F");
        assertThat("Cursor must not contain standard-Base64 '+'", cursor.contains("+"), is(false));
        assertThat("Cursor must not contain standard-Base64 '/'", cursor.contains("/"), is(false));
        assertThat("Cursor must not contain Base64 padding '='", cursor.contains("="), is(false));
    }

    @Test
    public void cursorRoundTrip_preservesUnicodeLastName() throws IOException {
        // Non-ASCII entity name — encode, then decode via parseAndValidate — the recovered lastName
        // must match byte-for-byte. Guards against silent character corruption in the codec.
        final String weirdName = "role-\u00E9\u4E2D\uD83D\uDE00";
        final String cursor = PaginationHelper.encodeCursor(CType.ROLES, PaginationHelper.SORT_ASC, weirdName);
        final var request = withParams(Map.of("next_token", cursor));
        final var result = PaginationHelper.parseAndValidate(request, CType.ROLES);
        assertThat(result.isValid(), is(true));
        result.valid(params -> assertThat(params.lastName(), is(weirdName)));
    }

    // ---------------------------------------------------------------------
    // apply – single-entity GET must reject pagination params
    // ---------------------------------------------------------------------

    @Test
    public void apply_rejectsPaginationOnSingleEntityGet() throws IOException {
        final var request = withParams(Map.of("size", "5", "sort", "asc"));
        final var configuration = rolesConfig(List.of("role_a", "role_b"));
        final var securityConfig = SecurityConfiguration.of("role_a", configuration);
        final var result = PaginationHelper.apply(request, CType.ROLES, securityConfig);
        assertThat(result.isValid(), is(false));
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void apply_returnsUnchangedConfigurationWhenNoPaginationParams() throws IOException {
        final var request = withParams(Map.of());
        final var configuration = rolesConfig(List.of("role_a", "role_b"));
        final var securityConfig = SecurityConfiguration.of(null, configuration);
        final var result = PaginationHelper.apply(request, CType.ROLES, securityConfig);
        assertThat(result.isValid(), is(true));
        // When no pagination parameters, the raw configuration is returned so responses remain
        // byte-identical to the pre-existing shape.
        final JsonNode json = renderToJson(result);
        assertThat(json.has("next_token"), is(false));
        assertThat(json.has("role_a"), is(true));
        assertThat(json.has("role_b"), is(true));
    }

    // ---------------------------------------------------------------------
    // Pagination traversal – asc/desc, multiple pages, terminal null
    // ---------------------------------------------------------------------

    @Test
    public void pagination_traversalAscending_multiPage() throws IOException {
        final var configuration = rolesConfig(List.of("d", "a", "c", "b"));
        // Page 1 (size=2, asc): expect [a, b], next_token != null
        final var page1 = renderToJson(
            PaginationHelper.apply(
                withParams(Map.of("size", "2", "sort", "asc")),
                CType.ROLES,
                SecurityConfiguration.of(null, configuration)
            )
        );
        assertThat(page1.get("next_token").isString(), is(true));
        assertThat(pageEntryNames(page1), contains("a", "b"));

        // Page 2 using returned cursor: expect [c, d], next_token == null (terminal)
        final String token1 = page1.get("next_token").asString();
        final var page2 = renderToJson(
            PaginationHelper.apply(
                withParams(Map.of("size", "2", "sort", "asc", "next_token", token1)),
                CType.ROLES,
                SecurityConfiguration.of(null, configuration)
            )
        );
        assertThat(page2.get("next_token").isNull(), is(true));
        assertThat(pageEntryNames(page2), contains("c", "d"));
    }

    @Test
    public void pagination_traversalDescending_multiPage() throws IOException {
        final var configuration = rolesConfig(List.of("d", "a", "c", "b"));
        final var page1 = renderToJson(
            PaginationHelper.apply(
                withParams(Map.of("size", "2", "sort", "desc")),
                CType.ROLES,
                SecurityConfiguration.of(null, configuration)
            )
        );
        assertThat(page1.get("next_token").isString(), is(true));
        assertThat(pageEntryNames(page1), contains("d", "c"));

        final String token1 = page1.get("next_token").asString();
        final var page2 = renderToJson(
            PaginationHelper.apply(
                withParams(Map.of("size", "2", "sort", "desc", "next_token", token1)),
                CType.ROLES,
                SecurityConfiguration.of(null, configuration)
            )
        );
        assertThat(page2.get("next_token").isNull(), is(true));
        assertThat(pageEntryNames(page2), contains("b", "a"));
    }

    @Test
    public void pagination_terminalPageEqualsFullSet_nullToken() throws IOException {
        final var configuration = rolesConfig(List.of("a", "b"));
        final var page = renderToJson(
            PaginationHelper.apply(
                withParams(Map.of("size", "5", "sort", "asc")),
                CType.ROLES,
                SecurityConfiguration.of(null, configuration)
            )
        );
        assertThat(page.get("next_token").isNull(), is(true));
        assertThat(pageEntryNames(page), contains("a", "b"));
    }

    @Test
    public void pagination_emptyCollection_yieldsEmptyPageAndNullToken() throws IOException {
        final var configuration = rolesConfig(List.of());
        final var page = renderToJson(
            PaginationHelper.apply(
                withParams(Map.of("size", "5", "sort", "asc")),
                CType.ROLES,
                SecurityConfiguration.of(null, configuration)
            )
        );
        assertThat(page.get("next_token").isNull(), is(true));
        assertThat(page.get("roles"), is(notNullValue()));
        assertThat(pageEntryNames(page), is(empty()));
    }

    // ---------------------------------------------------------------------
    // Lexical continuation – deletions/additions between pages do not shift
    // ---------------------------------------------------------------------

    @Test
    public void pagination_lexicalContinuation_deletedCursorNameStillResumesCorrectly() throws IOException {
        // Page 1 sees roles [a, b, c, d]; caller asks for size=2 asc => returns [a, b], cursor "b".
        final var configPage1 = rolesConfig(List.of("a", "b", "c", "d"));
        final var page1 = renderToJson(
            PaginationHelper.apply(withParams(Map.of("size", "2", "sort", "asc")), CType.ROLES, SecurityConfiguration.of(null, configPage1))
        );
        assertThat(pageEntryNames(page1), contains("a", "b"));
        final String cursor = page1.get("next_token").asString();

        // Between requests, role "b" (the cursor's last-name) was deleted. Also role "a" (before
        // the cursor) was deleted, and a new role "aa" was inserted before the cursor. Neither
        // should shift the continuation — we must still resume from names strictly after "b".
        final var configPage2 = rolesConfig(List.of("aa", "c", "d"));
        final var page2 = renderToJson(
            PaginationHelper.apply(
                withParams(Map.of("size", "2", "sort", "asc", "next_token", cursor)),
                CType.ROLES,
                SecurityConfiguration.of(null, configPage2)
            )
        );
        assertThat(pageEntryNames(page2), contains("c", "d"));
        assertThat(page2.get("next_token").isNull(), is(true));
    }

    // ---------------------------------------------------------------------
    // Response shape – contains paginated entity key and next_token
    // ---------------------------------------------------------------------

    @Test
    public void pagination_responseShape_wrapsUnderCTypeKey() throws IOException {
        final var configuration = rolesConfig(List.of("role_a"));
        final var page = renderToJson(
            PaginationHelper.apply(
                withParams(Map.of("size", "10", "sort", "asc")),
                CType.ROLES,
                SecurityConfiguration.of(null, configuration)
            )
        );
        assertThat(page.has("next_token"), is(true));
        assertThat(page.has(CType.ROLES.toLCString()), is(true));
        // No mixed shape: entries must live under the wrapper, not at the top level
        assertThat(page.has("role_a"), is(false));
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private static FakeRestRequest withParams(final Map<String, String> params) {
        return FakeRestRequest.builder().withParams(params).build();
    }

    /**
     * Renders a valid {@link ValidationResult} of a {@link ToXContent} to a JSON node so tests can
     * assert on the wire shape. Fails the test if the result is not valid.
     */
    private static JsonNode renderToJson(final ValidationResult<ToXContent> result) throws IOException {
        if (!result.isValid()) {
            throw new AssertionError("Expected a valid pagination result but got status " + result.status());
        }
        // Extract the ToXContent via the terminal `valid` consumer.
        final ToXContent[] captured = new ToXContent[1];
        result.valid(toXContent -> captured[0] = toXContent);
        try (var builder = XContentFactory.jsonBuilder()) {
            captured[0].toXContent(builder, ToXContent.EMPTY_PARAMS);
            return DefaultObjectMapper.readTree(builder.toString());
        }
    }

    /**
     * Builds a {@link SecurityDynamicConfiguration} of roles containing the given names, each with
     * a trivial {@code cluster_permissions: [*]} body — enough to exercise Jackson serialization
     * within the pagination helper.
     */
    private static SecurityDynamicConfiguration<RoleV7> rolesConfig(final List<String> names) throws IOException {
        final var mapper = DefaultObjectMapper.objectMapper();
        // Use a LinkedHashMap-backed ObjectNode so JSON encoding is deterministic across runs.
        final var config = mapper.createObjectNode();
        // _meta is expected on the raw index format; the API removes it during omitSensitiveData.
        // For unit-test purposes we omit it — SecurityDynamicConfiguration.fromJson tolerates its absence
        // when the type matches the constructor.
        for (final String name : names) {
            final var role = mapper.createObjectNode();
            role.set("cluster_permissions", mapper.createArrayNode().add("*"));
            config.set(name, role);
        }
        // Attach a _meta so fromJson accepts the payload.
        config.set("_meta", mapper.createObjectNode().put("type", CType.ROLES.toLCString()).put("config_version", 2));
        return SecurityDynamicConfiguration.fromJson(mapper.writeValueAsString(config), CType.ROLES, 2, 1, 1);
    }

    /**
     * Produces a valid cursor for {@code CType.ROLES} at asc order for "role_a", then applies the
     * given text transformation to simulate a tampered token. Uses URL-safe Base64 to match the
     * production {@link PaginationHelper#encodeCursor} encoding.
     */
    private static String tamperCursor(final java.util.function.Function<String, String> mutator) {
        final String cursor = PaginationHelper.encodeCursor(CType.ROLES, PaginationHelper.SORT_ASC, "role_a");
        final String decoded = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
        final String mutated = mutator.apply(decoded);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mutated.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Extracts the ordered list of entry names under the paginated response's ctype-keyed wrapper.
     */
    private static List<String> pageEntryNames(final JsonNode page) {
        final JsonNode wrapper = page.get(CType.ROLES.toLCString());
        final List<String> out = new java.util.ArrayList<>();
        wrapper.propertyNames().forEach(out::add);
        return out;
    }
}
