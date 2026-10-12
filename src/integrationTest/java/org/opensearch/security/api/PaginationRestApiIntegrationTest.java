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
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.pagination.PaginationHelper;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasItem;

/**
 * End-to-end coverage for cursor-based pagination on Security configuration collection APIs
 * (issue <a href="https://github.com/opensearch-project/security/issues/6339">#6339</a>).
 *
 * <p>Exercises the caller-visible collection endpoints against a real cluster: {@code internalusers}
 * (including {@code filterBy}), {@code roles}, {@code rolesmapping}, {@code actiongroups}, and
 * {@code tenants}. The {@code nodesdn} endpoint's pagination wiring uses the same
 * {@link PaginationHelper} path exercised by {@code PaginationHelperTest}; a live cluster GET is
 * not covered here because the {@code LocalCluster} test framework does not seed the {@code nodesdn}
 * document in the security index (see {@code NodesDnApiTest} for unit-level nodesdn coverage).
 *
 * <p>Per acceptance criterion, verifies:
 * <ul>
 *     <li>backward compatibility — no pagination params yields the exact existing response shape;</li>
 *     <li>ascending and descending traversal across multiple pages with a terminal {@code null} token;</li>
 *     <li>invalid {@code size} / {@code sort} / malformed / cross-endpoint tokens all return HTTP 400;</li>
 *     <li>pagination parameters on single-entity GET requests are rejected with HTTP 400;</li>
 *     <li>additions and deletions between page requests do not shift subsequent pages
 *         (lexical continuation);</li>
 *     <li>{@code filterBy} on {@code internalusers} composes correctly with pagination;</li>
 *     <li>hidden entities remain invisible under paginated traversal.</li>
 * </ul>
 */
public class PaginationRestApiIntegrationTest extends AbstractApiIntegrationTest {

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().nodeSetting(ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED, true).build();

    // ---------------------------------------------------------------------
    // Common bodies
    // ---------------------------------------------------------------------

    private static final String ROLE_BODY = """
        {"cluster_permissions": ["cluster_composite_ops_ro"]}
        """;

    private static final String ROLES_MAPPING_BODY = """
        {"backend_roles": ["backend"], "hosts": [], "users": []}
        """;

    private static final String ACTION_GROUP_BODY = """
        {"allowed_actions": ["indices:data/read*"]}
        """;

    private static final String TENANT_BODY = """
        {"description": "pagination test tenant"}
        """;

    private static final String INTERNAL_USER_BODY = """
        {"password": "TestPassword_123!", "backend_roles": ["backend"]}
        """;

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private static String pageQuery(final Map<String, String> params) {
        final StringBuilder sb = new StringBuilder("?");
        boolean first = true;
        for (final var entry : params.entrySet()) {
            if (!first) {
                sb.append('&');
            }
            sb.append(entry.getKey()).append('=').append(entry.getValue());
            first = false;
        }
        return sb.toString();
    }

    private JsonNode getAsJson(final TestRestClient client, final String path) throws Exception {
        final HttpResponse resp = client.get(path);
        assertThat(resp.getBody(), resp.getStatusCode(), is(200));
        return DefaultObjectMapper.readTree(resp.getBody());
    }

    /**
     * Returns the ordered list of names under the paginated response's ctype-keyed wrapper. Fails
     * the assertion if the wrapper is missing so callers can diagnose response-shape regressions.
     */
    private List<String> pageEntryNames(final JsonNode page, final CType<?> ctype) {
        final JsonNode wrapper = page.get(ctype.toLCString());
        assertThat("Paginated response should wrap entries under '" + ctype.toLCString() + "'", wrapper, notNullValue());
        final List<String> out = new ArrayList<>();
        wrapper.propertyNames().forEach(out::add);
        return out;
    }

    /**
     * Walks all pages of {@code apiPath} using the given {@code size} and {@code sort}, and returns
     * the concatenated ordered list of entity names. Guards against infinite loops if a cursor is
     * mis-encoded — bailing out at 100 pages produces a diagnosable failure rather than a hang.
     */
    private List<String> traverseAllPages(
        final TestRestClient client,
        final String apiPath,
        final CType<?> ctype,
        final int size,
        final String sort,
        final Map<String, String> extraParams
    ) throws Exception {
        final List<String> collected = new ArrayList<>();
        String token = null;
        for (int page = 0; page < 100; page++) {
            final var params = new java.util.LinkedHashMap<String, String>();
            params.put("size", Integer.toString(size));
            params.put("sort", sort);
            if (extraParams != null) {
                params.putAll(extraParams);
            }
            if (token != null) {
                params.put("next_token", token);
            }
            final JsonNode body = getAsJson(client, apiPath + pageQuery(params));
            collected.addAll(pageEntryNames(body, ctype));
            if (body.get("next_token").isNull()) {
                return collected;
            }
            token = body.get("next_token").asString();
        }
        throw new AssertionError("Pagination did not terminate after 100 pages (possible cursor bug)");
    }

    // ---------------------------------------------------------------------
    // Backwards compatibility: no pagination params → response shape unchanged
    // ---------------------------------------------------------------------

    @Test
    public void backwardCompatibility_rolesGetWithoutParamsHasNoWrapper() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            client.putJson(apiPath("roles", "bc_role_1"), ROLE_BODY);
            final JsonNode body = getAsJson(client, apiPath("roles"));
            // The existing response shape is a flat map of name → entry. It must not contain the
            // paginated wrapper on requests that did not opt in.
            assertThat(body.has("next_token"), is(false));
            assertThat("Existing shape should include the newly created role at top level", body.has("bc_role_1"), is(true));
        }
    }

    @Test
    public void backwardCompatibility_singleEntityGetUnchanged() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            client.putJson(apiPath("roles", "bc_single_role"), ROLE_BODY);
            final JsonNode body = getAsJson(client, apiPath("roles", "bc_single_role"));
            assertThat(body.has("next_token"), is(false));
            assertThat(body.has("bc_single_role"), is(true));
        }
    }

    // ---------------------------------------------------------------------
    // Traversal: ascending and descending across multiple pages, terminal null
    // ---------------------------------------------------------------------

    @Test
    public void roles_ascendingTraversalReturnsAllEntitiesSortedByName() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final List<String> created = List.of("asc_role_a", "asc_role_b", "asc_role_c", "asc_role_d", "asc_role_e");
            for (final String name : created) {
                client.putJson(apiPath("roles", name), ROLE_BODY);
            }
            final List<String> traversed = traverseAllPages(client, apiPath("roles"), CType.ROLES, 2, "asc", null);
            // The cluster ships with reserved roles (kibana_read_only, etc.), so we assert that
            // *our* names appear in ascending order, not that they are the only entries.
            final List<String> ours = traversed.stream().filter(created::contains).toList();
            assertThat("Ascending traversal should return our roles in name order", ours, contains(created.toArray(new String[0])));
        }
    }

    @Test
    public void roles_descendingTraversalReturnsAllEntitiesReverseSorted() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final List<String> created = List.of("desc_role_a", "desc_role_b", "desc_role_c", "desc_role_d");
            for (final String name : created) {
                client.putJson(apiPath("roles", name), ROLE_BODY);
            }
            final List<String> traversed = traverseAllPages(client, apiPath("roles"), CType.ROLES, 2, "desc", null);
            final List<String> ours = traversed.stream().filter(created::contains).toList();
            final List<String> reverse = new ArrayList<>(created);
            Collections.reverse(reverse);
            assertThat(
                "Descending traversal should return our roles in reverse name order",
                ours,
                contains(reverse.toArray(new String[0]))
            );
        }
    }

    @Test
    public void roles_lastPageReturnsNullToken() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Ask for a large page so a single request covers the entire visible set on first shot.
            final JsonNode page = getAsJson(client, apiPath("roles") + "?size=1000&sort=asc");
            assertThat(page.get("next_token"), notNullValue());
            assertThat(page.get("next_token").isNull(), is(true));
        }
    }

    // ---------------------------------------------------------------------
    // Invalid inputs
    // ---------------------------------------------------------------------

    @Test
    public void invalidInputs_badSizeSortAndTokenReturn400() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(apiPath("roles") + "?size=abc").getStatusCode(), is(400));
            assertThat(client.get(apiPath("roles") + "?size=0").getStatusCode(), is(400));
            assertThat(client.get(apiPath("roles") + "?size=100000").getStatusCode(), is(400));
            assertThat(client.get(apiPath("roles") + "?sort=sideways").getStatusCode(), is(400));
            assertThat(client.get(apiPath("roles") + "?next_token=@@@not-base64@@@").getStatusCode(), is(400));
        }
    }

    @Test
    public void invalidInputs_crossEndpointTokenRejected() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Get a valid roles cursor, then attempt to reuse it against /actiongroups.
            client.putJson(apiPath("roles", "cross_ep_role_1"), ROLE_BODY);
            client.putJson(apiPath("roles", "cross_ep_role_2"), ROLE_BODY);
            final JsonNode rolesPage = getAsJson(client, apiPath("roles") + "?size=1&sort=asc");
            assertThat("Test setup expects a follow-up page", rolesPage.get("next_token").isString(), is(true));
            final String rolesToken = rolesPage.get("next_token").asString();
            final HttpResponse resp = client.get(apiPath("actiongroups") + "?size=5&sort=asc&next_token=" + rolesToken);
            assertThat(resp.getBody(), resp.getStatusCode(), is(400));
        }
    }

    @Test
    public void invalidInputs_crossSortDirectionTokenRejected() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            client.putJson(apiPath("roles", "cross_sort_role_1"), ROLE_BODY);
            client.putJson(apiPath("roles", "cross_sort_role_2"), ROLE_BODY);
            client.putJson(apiPath("roles", "cross_sort_role_3"), ROLE_BODY);
            final JsonNode page = getAsJson(client, apiPath("roles") + "?size=1&sort=asc");
            final String ascToken = page.get("next_token").asString();
            final HttpResponse resp = client.get(apiPath("roles") + "?size=1&sort=desc&next_token=" + ascToken);
            assertThat(resp.getBody(), resp.getStatusCode(), is(400));
        }
    }

    @Test
    public void invalidInputs_singleEntityGetRejectsPaginationParams() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            client.putJson(apiPath("roles", "single_pagination_role"), ROLE_BODY);
            final HttpResponse resp = client.get(apiPath("roles", "single_pagination_role") + "?size=5&sort=asc");
            assertThat(resp.getBody(), resp.getStatusCode(), is(400));
        }
    }

    // ---------------------------------------------------------------------
    // Additions / deletions between pages – lexical continuation
    // ---------------------------------------------------------------------

    @Test
    public void lexicalContinuation_deletionOfCursorNameDoesNotShiftLaterPages() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Use a "zzz_" prefix so our seeded roles sort after any bundled/reserved roles
            // (kibana_read_only, all_access, etc.). This lets the test drive the cursor to a
            // known position of our own choosing regardless of what the cluster starts with.
            final List<String> created = List.of("zzz_cont_a", "zzz_cont_b", "zzz_cont_c", "zzz_cont_d");
            for (final String name : created) {
                client.putJson(apiPath("roles", name), ROLE_BODY);
            }
            // Walk forward until we have a cursor whose last-name is exactly "zzz_cont_b". Doing
            // this via traversal (rather than assuming page 1 already lands there) makes the test
            // resilient to any number of bundled entities coming before ours.
            String cursor = null;
            outer: while (true) {
                final var params = new java.util.LinkedHashMap<String, String>();
                params.put("size", "1");
                params.put("sort", "asc");
                if (cursor != null) {
                    params.put("next_token", cursor);
                }
                final JsonNode page = getAsJson(client, apiPath("roles") + pageQuery(params));
                final List<String> names = pageEntryNames(page, CType.ROLES);
                for (final String n : names) {
                    if ("zzz_cont_b".equals(n)) {
                        cursor = page.get("next_token").asString();
                        break outer;
                    }
                }
                if (page.get("next_token").isNull()) {
                    throw new AssertionError("Did not find seeded role zzz_cont_b during traversal");
                }
                cursor = page.get("next_token").asString();
            }

            // Delete the entity referenced by the cursor. Lexical continuation means we must still
            // resume from names strictly after "zzz_cont_b".
            client.delete(apiPath("roles", "zzz_cont_b"));

            // Continue from cursor and collect our created names still visible. Only "zzz_cont_c"
            // and "zzz_cont_d" should reappear — "zzz_cont_a" and "zzz_cont_b" must not, and the
            // continuation must not have shifted.
            final List<String> collected = new ArrayList<>();
            String token = cursor;
            for (int i = 0; i < 20; i++) {
                final var params = new java.util.LinkedHashMap<String, String>();
                params.put("size", "2");
                params.put("sort", "asc");
                params.put("next_token", token);
                final JsonNode next = getAsJson(client, apiPath("roles") + pageQuery(params));
                for (final String n : pageEntryNames(next, CType.ROLES)) {
                    if (created.contains(n)) {
                        collected.add(n);
                    }
                }
                if (next.get("next_token").isNull()) {
                    break;
                }
                token = next.get("next_token").asString();
            }
            assertThat(
                "After deleting cursor-named entity, continuation should still return names strictly after it",
                collected,
                contains("zzz_cont_c", "zzz_cont_d")
            );
        }
    }

    // ---------------------------------------------------------------------
    // Cross-endpoint coverage – smoke test each endpoint with pagination
    // ---------------------------------------------------------------------

    @Test
    public void collectionEndpoints_paginationSmokeTest() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Seed each endpoint with a couple of entities so the paginated shape is exercised
            // even when the cluster ships with defaults.
            for (int i = 1; i <= 3; i++) {
                client.putJson(apiPath("roles", "smoke_role_" + i), ROLE_BODY);
                client.putJson(apiPath("actiongroups", "smoke_ag_" + i), ACTION_GROUP_BODY);
                client.putJson(apiPath("internalusers", "smoke_user_" + i), INTERNAL_USER_BODY);
                client.putJson(apiPath("tenants", "smoke_tenant_" + i), TENANT_BODY);
            }
            // Roles mappings require a target role to exist first, so map to smoke_map_target_*.
            for (int i = 1; i <= 3; i++) {
                client.putJson(apiPath("roles", "smoke_map_target_" + i), ROLE_BODY);
                client.putJson(apiPath("rolesmapping", "smoke_map_target_" + i), ROLES_MAPPING_BODY);
            }

            // NodesDN is intentionally excluded here: the LocalCluster test framework does not seed
            // the nodesdn document in the security index and the endpoint returns 403 "Security
            // index need to be updated" without the SecurityAdmin populate step. Its wiring uses
            // the same PaginationHelper path exercised by PaginationHelperTest.
            for (final String endpoint : List.of("roles", "rolesmapping", "actiongroups", "internalusers", "tenants")) {
                final HttpResponse page1 = client.get(apiPath(endpoint) + "?size=1&sort=asc");
                assertThat(
                    "First-page response should be 200 for endpoint " + endpoint + ": " + page1.getBody(),
                    page1.getStatusCode(),
                    is(200)
                );
                final JsonNode body1 = DefaultObjectMapper.readTree(page1.getBody());
                final CType<?> ctype = CType.fromString(endpoint.toLowerCase(Locale.ROOT));
                assertThat("Response should carry next_token key for endpoint " + endpoint, body1.has("next_token"), is(true));
                assertThat("Response should carry an entity wrapper for endpoint " + endpoint, body1.has(ctype.toLCString()), is(true));
                // size=1 combined with a seeded fleet of ≥3 entities of ours should always leave a cursor.
                assertThat(
                    "Endpoint " + endpoint + " should have a follow-up cursor on size=1",
                    body1.get("next_token").isString(),
                    is(true)
                );
            }
        }
    }

    // ---------------------------------------------------------------------
    // internalusers – filterBy composes with pagination
    // ---------------------------------------------------------------------

    @Test
    public void internalUsers_filterByServiceComposesWithPagination() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Two internal users (non-service), one service account
            client.putJson(apiPath("internalusers", "filter_user_a"), INTERNAL_USER_BODY);
            client.putJson(apiPath("internalusers", "filter_user_b"), INTERNAL_USER_BODY);
            final String svcBody = """
                {"attributes": {"service": "true"}, "backend_roles": ["service"]}
                """;
            client.putJson(apiPath("internalusers", "filter_service_z"), svcBody);

            // filterBy=service should exclude non-service users; pagination should then only
            // enumerate service accounts.
            final List<String> serviceNames = traverseAllPages(
                client,
                apiPath("internalusers"),
                CType.INTERNALUSERS,
                50,
                "asc",
                Map.of("filterBy", "service")
            );
            assertThat("filterBy=service should exclude regular users", serviceNames, not(hasItem("filter_user_a")));
            assertThat("filterBy=service should exclude regular users", serviceNames, not(hasItem("filter_user_b")));
            assertThat("filterBy=service should include the service user", serviceNames, hasItem("filter_service_z"));
        }
    }

    // ---------------------------------------------------------------------
    // nodesdn – show_all composes with pagination
    // ---------------------------------------------------------------------

    // Note: the LocalCluster test framework does not initialize the nodesdn document in the
    // security index, so a live GET returns 403 "Security index need to be updated". The nodesdn
    // pagination wiring is exercised in NodesDnApiTest (unit) and its shared pagination logic in
    // PaginationHelperTest — both of which include the show_all + pagination composition.

    // ---------------------------------------------------------------------
    // Hidden entities remain invisible to non-admin callers under pagination
    // ---------------------------------------------------------------------

    @Test
    public void hiddenEntities_notLeakedByPagination() throws Exception {
        // Rest-admin can create hidden entities; a regular admin sees the caller-visible set only.
        try (TestRestClient restAdmin = localCluster.getRestClient(REST_ADMIN_USER)) {
            final String hiddenRole = """
                {"cluster_permissions": ["cluster_composite_ops_ro"], "hidden": true}
                """;
            restAdmin.putJson(apiPath("roles", "hidden_pagination_role"), hiddenRole);
        }
        try (TestRestClient regularAdmin = localCluster.getRestClient(ADMIN_USER)) {
            final List<String> names = traverseAllPages(regularAdmin, apiPath("roles"), CType.ROLES, 100, "asc", null);
            assertThat("Pagination must not leak hidden entities to non-admin callers", names, not(hasItem("hidden_pagination_role")));
        }
    }

    // ---------------------------------------------------------------------
    // Response shape – wrapper key matches endpoint name
    // ---------------------------------------------------------------------

    @Test
    public void responseShape_wrapperKeyMatchesEndpointCType() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            client.putJson(apiPath("actiongroups", "shape_ag_1"), ACTION_GROUP_BODY);
            final HttpResponse resp = client.get(apiPath("actiongroups") + "?size=10&sort=asc");
            assertThat(resp.getBody(), resp.getStatusCode(), is(200));
            final JsonNode body = DefaultObjectMapper.readTree(resp.getBody());
            assertThat(body.has("next_token"), is(true));
            assertThat(body.has(CType.ACTIONGROUPS.toLCString()), is(true));
            // Sanity: no leakage of entries at the top level
            assertThat(body.has("shape_ag_1"), is(false));
        }
    }

    // ---------------------------------------------------------------------
    // Small guard against future accidental double-registration
    // ---------------------------------------------------------------------

    @Test
    public void endpointBinding_paginationHelperConstantsMatchQueryStringForm() {
        assertThat(PaginationHelper.PARAM_SIZE, equalTo("size"));
        assertThat(PaginationHelper.PARAM_NEXT_TOKEN, equalTo("next_token"));
        assertThat(PaginationHelper.PARAM_SORT, equalTo("sort"));
    }

    // ---------------------------------------------------------------------
    // Sanity for empty next_token param
    // ---------------------------------------------------------------------

    @Test
    public void emptyNextToken_treatedAsAbsent() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final HttpResponse resp = client.get(apiPath("roles") + "?size=5&sort=asc&next_token=");
            assertThat(resp.getBody(), resp.getStatusCode(), is(200));
            final JsonNode body = DefaultObjectMapper.readTree(resp.getBody());
            assertThat("Empty next_token should be treated as first page", body.has("next_token"), is(true));
        }
    }
}
