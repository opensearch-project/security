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

package org.opensearch.security.api;

import java.util.ArrayList;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.dlic.rest.api.pagination.PaginationParams;
import org.opensearch.security.dlic.rest.api.pagination.PaginationRequestParser;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;

/**
 * Integration tests for pagination on Security config collection GET APIs.
 *
 * Covered APIs: roles, internalusers, rolesmapping, actiongroups, tenants
 */
public class PaginationRestApiIntegrationTest extends AbstractApiIntegrationTest {

    private static final String SIZE = PaginationRequestParser.PARAM_SIZE;
    private static final String SORT = PaginationRequestParser.PARAM_SORT;
    private static final String TOKEN = PaginationRequestParser.PARAM_NEXT_TOKEN;
    private static final String NEXT = PaginationRequestParser.RESPONSE_NEXT_TOKEN_KEY;

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().build();

    /** Appends ?key=val&… to an already-built API path. */
    private static String withParams(final String path, final String... kvPairs) {
        final var sb = new StringBuilder(path).append('?');
        for (int i = 0; i < kvPairs.length; i += 2) {
            if (i > 0) sb.append('&');
            sb.append(kvPairs[i]).append('=').append(kvPairs[i + 1]);
        }
        return sb.toString();
    }

    @Test
    public void nonPaginatedGetReturnsLegacyFlatShape() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var resp = ok(() -> client.get(apiPath("roles")));
            final var body = resp.bodyAsJsonNode();
            // Legacy response has NO next_token field
            assertThat("legacy response must not contain next_token", body.has(NEXT), is(false));
            assertThat(body.size(), greaterThan(0));
        }
    }

    // ── single-page response when size ≥ total ──
    @Test
    public void largeSizeReturnsAllRolesOnOnePage() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var resp = ok(() -> client.get(withParams(apiPath("roles"), SIZE, "1000")));
            final var body = resp.bodyAsJsonNode();

            assertThat(body.has(NEXT), is(true));
            assertThat("terminal page next_token must be null", body.get(NEXT).isNull(), is(true));
            assertThat(body.get("roles").size(), greaterThan(0));
        }
    }

    // ── ascending multi-page traversal ──

    @Test
    public void ascendingTraversalCoversAllRoles() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Fetch total count via non-paginated request
            final int totalRoles = ok(() -> client.get(apiPath("roles"))).bodyAsJsonNode().size();

            final var allSeen = new ArrayList<String>();
            String nextToken = null;

            do {
                final String path = nextToken == null
                    ? withParams(apiPath("roles"), SIZE, "2", SORT, "asc")
                    : withParams(apiPath("roles"), SIZE, "2", SORT, "asc", TOKEN, nextToken);

                final var resp = ok(() -> client.get(path));
                final var body = resp.bodyAsJsonNode();

                assertThat("paginated response must have roles key", body.has("roles"), is(true));
                assertThat("paginated response must have next_token key", body.has(NEXT), is(true));

                body.get("roles").propertyNames().forEach(allSeen::add);
                nextToken = body.get(NEXT).isNull() ? null : body.get(NEXT).asText();
            } while (nextToken != null);

            assertThat("traversal must cover all roles", allSeen.size(), is(totalRoles));
            // Verify ascending order
            for (int i = 1; i < allSeen.size(); i++) {
                assertThat(
                    allSeen.get(i - 1) + " must sort before " + allSeen.get(i),
                    allSeen.get(i - 1).compareTo(allSeen.get(i)) < 0,
                    is(true)
                );
            }
        }
    }

    @Test
    public void descendingTraversalCoversAllRoles() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final int totalRoles = ok(() -> client.get(apiPath("roles"))).bodyAsJsonNode().size();

            final var allSeen = new ArrayList<String>();
            String nextToken = null;

            do {
                final String path = nextToken == null
                    ? withParams(apiPath("roles"), SIZE, "2", SORT, "desc")
                    : withParams(apiPath("roles"), SIZE, "2", SORT, "desc", TOKEN, nextToken);

                final var body = ok(() -> client.get(path)).bodyAsJsonNode();
                body.get("roles").propertyNames().forEach(allSeen::add);
                nextToken = body.get(NEXT).isNull() ? null : body.get(NEXT).asText();
            } while (nextToken != null);

            assertThat("descending traversal must cover all roles", allSeen.size(), is(totalRoles));
            // Verify descending order
            for (int i = 1; i < allSeen.size(); i++) {
                assertThat(
                    allSeen.get(i - 1) + " must sort after " + allSeen.get(i),
                    allSeen.get(i - 1).compareTo(allSeen.get(i)) > 0,
                    is(true)
                );
            }
        }
    }

    // ── terminal page has null next_token ──

    @Test
    public void lastPageHasNullNextToken() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Request huge page — should return everything in one go
            final var body = ok(() -> client.get(withParams(apiPath("roles"), SIZE, "1000"))).bodyAsJsonNode();
            assertThat(body.get(NEXT).isNull(), is(true));
        }
    }

    // ── invalid params → 400 ──

    @Test
    public void zeroSizeReturnsBadRequest() {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(withParams(apiPath("roles"), SIZE, "0")), isBadRequest());
        }
    }

    @Test
    public void negativeSizeReturnsBadRequest() {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(withParams(apiPath("roles"), SIZE, "-1")), isBadRequest());
        }
    }

    @Test
    public void sizeAboveMaxReturnsBadRequest() {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(withParams(apiPath("roles"), SIZE, String.valueOf(PaginationParams.MAX_SIZE + 1))), isBadRequest());
        }
    }

    @Test
    public void nonIntegerSizeReturnsBadRequest() {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(withParams(apiPath("roles"), SIZE, "abc")), isBadRequest());
        }
    }

    @Test
    public void invalidSortReturnsBadRequest() {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(withParams(apiPath("roles"), SORT, "random")), isBadRequest());
        }
    }

    @Test
    public void malformedTokenReturnsBadRequest() {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(withParams(apiPath("roles"), TOKEN, "not-a-valid-token!!")), isBadRequest());
        }
    }

    @Test
    public void crossEndpointTokenReturnsBadRequest() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Get a valid token from roles
            final var resp = ok(() -> client.get(withParams(apiPath("roles"), SIZE, "1")));
            final var rolesToken = resp.bodyAsJsonNode().get(NEXT).asText();

            // Present it to a different endpoint
            assertThat(client.get(withParams(apiPath("internalusers"), TOKEN, rolesToken)), isBadRequest());
        }
    }

    @Test
    public void sortMismatchTokenReturnsBadRequest() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Get a token from an ascending request
            final var resp = ok(() -> client.get(withParams(apiPath("roles"), SIZE, "1", SORT, "asc")));
            final var ascToken = resp.bodyAsJsonNode().get(NEXT).asText();

            // Present it with a different sort direction
            assertThat(client.get(withParams(apiPath("roles"), SORT, "desc", TOKEN, ascToken)), isBadRequest());
        }
    }

    // ── single-entity GET + pagination params → 400 ──

    @Test
    public void paginationOnSingleEntityGetReturnsBadRequest() {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(withParams(apiPath("roles", "abcd"), SIZE, "5")), isBadRequest());
        }
    }

    // ── hidden entity not visible in paginated result ──

    @Test
    public void hiddenRolesNotLeakedInPaginatedResponse() throws Exception {
        final String hiddenRoleName = "pagination_test_hidden_role";
        // Create a hidden role via TLS admin (super-admin can set hidden=true)
        try (TestRestClient tlsClient = localCluster.getAdminCertRestClient()) {
            tlsClient.putJson(
                apiPath("roles", hiddenRoleName),
                (builder, params) -> builder.startObject().field("hidden", true).startArray("cluster_permissions").endArray().endObject()
            );
        }

        // Regular admin must not see the hidden role in paginated results
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var allSeen = new ArrayList<String>();
            String nextToken = null;

            do {
                final String path = nextToken == null
                    ? withParams(apiPath("roles"), SIZE, "50", SORT, "asc")
                    : withParams(apiPath("roles"), SIZE, "50", SORT, "asc", TOKEN, nextToken);
                final var body = ok(() -> client.get(path)).bodyAsJsonNode();
                body.get("roles").propertyNames().forEach(allSeen::add);
                nextToken = body.get(NEXT).isNull() ? null : body.get(NEXT).asText();
            } while (nextToken != null);

            assertThat("hidden role must not be visible in paginated output", allSeen.contains(hiddenRoleName), is(false));
        }
    }

    // ── pagination works across all six collection APIs ──

    @Test
    public void paginationWorksForInternalUsers() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var resp = ok(() -> client.get(withParams(apiPath("internalusers"), SIZE, "1000")));
            final var body = resp.bodyAsJsonNode();
            assertThat(body.has(NEXT), is(true));
            assertThat(body.has("internalusers"), is(true));
        }
    }

    @Test
    public void paginationWorksForRolesMapping() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var resp = ok(() -> client.get(withParams(apiPath("rolesmapping"), SIZE, "1000")));
            final var body = resp.bodyAsJsonNode();
            assertThat(body.has(NEXT), is(true));
            assertThat(body.has("rolesmapping"), is(true));
        }
    }

    @Test
    public void paginationWorksForActionGroups() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var resp = ok(() -> client.get(withParams(apiPath("actiongroups"), SIZE, "1000")));
            final var body = resp.bodyAsJsonNode();
            assertThat(body.has(NEXT), is(true));
            assertThat(body.has("actiongroups"), is(true));
        }
    }

    @Test
    public void paginationWorksForTenants() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var resp = ok(() -> client.get(withParams(apiPath("tenants"), SIZE, "1000")));
            final var body = resp.bodyAsJsonNode();
            assertThat(body.has(NEXT), is(true));
            assertThat(body.has("tenants"), is(true));
        }
    }

    // ── addition between pages does not break continuation ──

    @Test
    public void additionBetweenPageRequestsDoesNotBreakContinuation() throws Exception {
        final String newRoleName = "zzz_pagination_new_role";
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Get first page token
            final var firstPage = ok(() -> client.get(withParams(apiPath("roles"), SIZE, "2", SORT, "asc")));
            final var firstToken = firstPage.bodyAsJsonNode().get(NEXT).asText();

            // Add a new role that sorts AFTER existing ones (zzz prefix)
            client.putJson(
                apiPath("roles", newRoleName),
                (builder, params) -> builder.startObject().startArray("cluster_permissions").endArray().endObject()
            );

            // Continue pagination from the saved token — must not throw or 400
            final var secondPage = ok(() -> client.get(withParams(apiPath("roles"), SIZE, "2", SORT, "asc", TOKEN, firstToken)));
            assertThat(secondPage.bodyAsJsonNode().has("roles"), is(true));

            // Cleanup
            client.delete(apiPath("roles", newRoleName));
        }
    }

    // ── deletion between pages (cursor entity removed) ──

    @Test
    public void deletionOfCursorEntityDoesNotBreakContinuation() throws Exception {
        final String tempRoleName = "aaa_pagination_temp_role";
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Create a role that sorts first (aaa prefix)
            client.putJson(
                apiPath("roles", tempRoleName),
                (builder, params) -> builder.startObject().startArray("cluster_permissions").endArray().endObject()
            );

            // Get first page (size=1) — cursor should point to tempRoleName
            final var firstPage = ok(() -> client.get(withParams(apiPath("roles"), SIZE, "1", SORT, "asc")));
            final var token = firstPage.bodyAsJsonNode().get(NEXT).asText();

            // Delete the cursor entity
            client.delete(apiPath("roles", tempRoleName));

            // Continue from cursor — must succeed with lexical continuation
            final var nextPage = ok(() -> client.get(withParams(apiPath("roles"), SIZE, "2", SORT, "asc", TOKEN, token)));
            assertThat(nextPage.bodyAsJsonNode().has("roles"), is(true));
        }
    }
}
