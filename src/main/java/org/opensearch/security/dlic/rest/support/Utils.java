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

package org.opensearch.security.dlic.rest.support;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.tuple.Pair;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchParseException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.CheckedSupplier;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestHandler.DeprecatedRoute;
import org.opensearch.rest.RestHandler.Route;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;

import static org.opensearch.core.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;
import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class Utils {

    public final static String PLUGIN_ROUTE_PREFIX = "/" + PLUGINS_PREFIX;

    public final static String LEGACY_PLUGIN_ROUTE_PREFIX = "/" + LEGACY_OPENDISTRO_PREFIX;

    public final static String PLUGIN_API_ROUTE_PREFIX = PLUGIN_ROUTE_PREFIX + "/api";

    public final static String LEGACY_PLUGIN_API_ROUTE_PREFIX = LEGACY_PLUGIN_ROUTE_PREFIX + "/api";

    private static final ObjectMapper internalMapper = new ObjectMapper();

    public static Map<String, Object> convertJsonToxToStructuredMap(ToXContent jsonContent) {
        Map<String, Object> map = null;
        try {
            final BytesReference bytes = XContentHelper.toXContent(jsonContent, XContentType.JSON, false);
            map = XContentHelper.convertToMap(bytes, false, XContentType.JSON).v2();
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToOpenSearchException(e1);
        }

        return map;
    }

    public static Map<String, Object> convertJsonToxToStructuredMap(String jsonContent) {
        try (
            XContentParser parser = XContentType.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, jsonContent)
        ) {
            return parser.map();
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToOpenSearchException(e1);
        }
    }

    private static BytesReference convertStructuredMapToBytes(Map<String, ?> structuredMap) {
        try {
            return BytesReference.bytes(JsonXContent.contentBuilder().map(structuredMap));
        } catch (IOException e) {
            throw new OpenSearchParseException("Failed to convert map", e);
        }
    }

    public static String convertStructuredMapToJson(Map<String, ?> structuredMap) {
        try {
            return XContentHelper.convertToJson(convertStructuredMapToBytes(structuredMap), false, XContentType.JSON);
        } catch (IOException e) {
            throw new OpenSearchParseException("Failed to convert map", e);
        }
    }

    public static JsonNode convertJsonToJackson(BytesReference jsonContent) {
        try {
            return DefaultObjectMapper.readTree(jsonContent.utf8ToString());
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToOpenSearchException(e1);
        }

    }

    public static JsonNode toJsonNode(final String content) throws IOException {
        return DefaultObjectMapper.readTree(content);
    }

    public static Object toConfigObject(final JsonNode content, final Class<?> clazz) throws IOException {
        return DefaultObjectMapper.readTree(content, clazz);
    }

    public static JsonNode convertJsonToJackson(ToXContent jsonContent, boolean omitDefaults) {
        try {
            Map<String, String> pm = new HashMap<>(1);
            pm.put("omit_defaults", String.valueOf(omitDefaults));
            ToXContent.MapParams params = new ToXContent.MapParams(pm);

            final BytesReference bytes = org.opensearch.core.xcontent.XContentHelper.toXContent(
                jsonContent,
                MediaTypeRegistry.JSON,
                params,
                false
            );
            return DefaultObjectMapper.readTree(bytes.utf8ToString());
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToOpenSearchException(e1);
        }

    }

    @SuppressWarnings("removal")
    public static byte[] jsonMapToByteArray(Map<String, Object> jsonAsMap) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<byte[]>) () -> internalMapper.writeValueAsBytes(jsonAsMap));
        } catch (final PrivilegedActionException e) {
            if (e.getCause() instanceof JsonProcessingException) {
                throw (JsonProcessingException) e.getCause();
            } else if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    @SuppressWarnings("removal")
    public static Map<String, Object> byteArrayToMutableJsonMap(byte[] jsonBytes) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(
                (PrivilegedExceptionAction<Map<String, Object>>) () -> internalMapper.readValue(
                    jsonBytes,
                    new TypeReference<Map<String, Object>>() {
                    }
                )
            );
        } catch (final PrivilegedActionException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            } else if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    /**
     * Generate field resource paths
     * @param fields fields
     * @param prefix prefix path
     * @return new set of fields resource paths
     */
    public static Set<String> generateFieldResourcePaths(final Set<String> fields, final String prefix) {
        return fields.stream().map(field -> prefix + field).collect(ImmutableSet.toImmutableSet());
    }

    /**
     * Add prefixes(_opendistro... and _plugins...) to rest API routes
     * @param routes routes
     * @return new list of API routes prefixed with _opendistro... and _plugins...
     *Total number of routes is expanded as twice as the number of routes passed in
     */
    public static List<Route> addRoutesPrefix(List<Route> routes) {
        return addRoutesPrefix(routes, LEGACY_PLUGIN_API_ROUTE_PREFIX, PLUGIN_API_ROUTE_PREFIX);
    }

    /**
     * Add customized prefix(_opendistro... and _plugins...)to API rest routes
     * @param routes routes
     * @param prefixes all api prefix
     * @return new list of API routes prefixed with the strings listed in prefixes
     * Total number of routes will be expanded len(prefixes) as much comparing to the list passed in
     */
    public static List<Route> addRoutesPrefix(List<Route> routes, final String... prefixes) {
        return routes.stream().flatMap(r -> Arrays.stream(prefixes).map(p -> {
            if (r instanceof NamedRoute) {
                NamedRoute nr = (NamedRoute) r;
                return new NamedRoute.Builder().method(nr.getMethod())
                    .path(p + nr.getPath())
                    .uniqueName(nr.name())
                    .legacyActionNames(nr.actionNames())
                    .build();
            }
            return new Route(r.getMethod(), p + r.getPath());
        })).collect(ImmutableList.toImmutableList());
    }

    /**
     * Add prefixes(_plugins...) to rest API routes
     * @param deprecatedRoutes Routes being deprecated
     * @return new list of API routes prefixed with _opendistro... and _plugins...
     *Total number of routes is expanded as twice as the number of routes passed in
     */
    public static List<DeprecatedRoute> addDeprecatedRoutesPrefix(List<DeprecatedRoute> deprecatedRoutes) {
        return addDeprecatedRoutesPrefix(deprecatedRoutes, LEGACY_PLUGIN_API_ROUTE_PREFIX, PLUGIN_API_ROUTE_PREFIX);
    }

    /**
     * Add customized prefix(_opendistro... and _plugins...)to API rest routes
     * @param deprecatedRoutes Routes being deprecated
     * @param prefixes all api prefix
     * @return new list of API routes prefixed with the strings listed in prefixes
     * Total number of routes will be expanded len(prefixes) as much comparing to the list passed in
     */
    public static List<DeprecatedRoute> addDeprecatedRoutesPrefix(List<DeprecatedRoute> deprecatedRoutes, final String... prefixes) {
        return deprecatedRoutes.stream()
            .flatMap(r -> Arrays.stream(prefixes).map(p -> new DeprecatedRoute(r.getMethod(), p + r.getPath(), r.getDeprecationMessage())))
            .collect(ImmutableList.toImmutableList());
    }

    public static Pair<User, TransportAddress> userAndRemoteAddressFrom(final ThreadContext threadContext) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final TransportAddress remoteAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        return Pair.of(user, remoteAddress);
    }

    public static <T> T withIOException(final CheckedSupplier<T, IOException> action) {
        try {
            return action.get();
        } catch (final IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

}
