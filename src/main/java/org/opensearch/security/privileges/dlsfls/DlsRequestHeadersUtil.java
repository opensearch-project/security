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

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.filter.SecurityRequestChannel;

import tools.jackson.core.type.TypeReference;

import static java.util.function.Function.identity;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_SECURITY_DLS_REQUEST_HEADERS;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_SECURITY_DLS_REQUEST_HEADERS_CONFIG;

/**
 * Utilities to handle request headers which are made available as attributes for substitution in DLS queries.
 */
public class DlsRequestHeadersUtil {
    private static final Logger log = LogManager.getLogger(DlsRequestHeadersUtil.class);

    private DlsRequestHeadersUtil() {}

    /**
     * Arbitrary upper limit on the amount of supported headers to prevent a DOS attack.
     * Since the headers are forwarded to requests to other shards sending a too big amount of headers could
     * negatively impact other shards.
     */
    private static final int MAX_HEADER_COUNT = 256;

    /**
     * It is possible to reference HTTP / gRPC headers in DLS queries. To achieve this, they are extracted from the
     * request and stored in the thread context in a manner where they will also be available if the request is
     * forwarded.
     */
    public static void extractAndStoreDlsRequestHeaders(
        final SecurityRequestChannel securityRequestChannel,
        final ThreadContext threadContext,
        final Settings settings
    ) {
        final var allowedDlsRequestHeaders = getDlsRequestHeaderSettings(settings);

        final Map<String, List<String>> rawDlsRequestHeaders = securityRequestChannel.getHeaders() == null
            ? Map.of()
            : securityRequestChannel.getHeaders()
                .entrySet()
                .stream()
                .filter(e -> allowedDlsRequestHeaders.keySet().stream().anyMatch(a -> a.equalsIgnoreCase(e.getKey())))
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));

        final var dlsRequestHeaders = rawDlsRequestHeaders.entrySet()
            .stream()
            .map(e -> toDlsRequestHeader(allowedDlsRequestHeaders.get(e.getKey().toLowerCase()), e.getKey(), e.getValue()))
            .toList();

        final var totalHeaderCount = rawDlsRequestHeaders.values().stream().mapToInt(List::size).sum();

        if (totalHeaderCount > MAX_HEADER_COUNT) {
            throw new IllegalArgumentException(
                String.format(
                    "found %d headers for DLS variables which exceeds the global maximum of %d",
                    totalHeaderCount,
                    MAX_HEADER_COUNT
                )
            );
        }

        log.debug(
            "found {} headers with a total of {} values which matched one of the {} allowlisted headers for DLS variables: {}",
            dlsRequestHeaders::size,
            () -> totalHeaderCount,
            allowedDlsRequestHeaders::size,
            rawDlsRequestHeaders::keySet
        );
        log.trace("allowlisted headers: {}", () -> allowedDlsRequestHeaders);

        // store it transiently for usage in this thread
        threadContext.putTransient(OPENSEARCH_SECURITY_DLS_REQUEST_HEADERS, dlsRequestHeaders);

        // and as a header so that it is passed on to other threads / instances, where it will be restored into a transient entry
        // See SecurityRequestHandler#messageReceivedDecorate
        if (!dlsRequestHeaders.isEmpty()) {
            final var serializedDlsRequestHeaders = DefaultObjectMapper.objectMapper().writerFor(new TypeReference<List<DlsRequestHeader>>() {
            }).writeValueAsString(dlsRequestHeaders);
            threadContext.putHeader(OPENSEARCH_SECURITY_DLS_REQUEST_HEADERS, serializedDlsRequestHeaders);
        }
    }

    /**
     * Validates the request header and, if it is valid, turns it into a {@link DlsRequestHeader}.
     * @throws IllegalArgumentException if the header value does not match the configured regex or has more than
     *                                  one value if it is flagged as single-value
     */
    private static DlsRequestHeader toDlsRequestHeader(
        final DlsRequestHeaderSettings dlsRequestHeaderSettings,
        final String headerName,
        final List<String> headerValues
    ) {
        for (final var headerValue : headerValues) {
            if (!dlsRequestHeaderSettings.validationPattern().matcher(headerValue).matches()) {
                throw new IllegalArgumentException(
                    String.format("header %s does not match the specified pattern and has thus been rejected!", headerName)
                );
            }
            if (headerValue.length() > dlsRequestHeaderSettings.maxValueLength()) {
                throw new IllegalArgumentException(
                    String.format(
                        "header %s exceeds the maximum defined length! (%d > %d)",
                        headerName,
                        headerValue.length(),
                        dlsRequestHeaderSettings.maxValueLength()
                    )
                );
            }
        }

        if (dlsRequestHeaderSettings.isMultiValue()) {
            return new MultiValueDlsRequestHeader(headerName, headerValues);
        } else {
            if (headerValues.size() != 1) {
                throw new IllegalArgumentException(
                    String.format(
                        "Received %d entries for header %s, but expected it to be a single value!",
                        headerValues.size(),
                        headerName
                    )
                );
            }
            return new SingleValueDlsRequestHeader(headerName, headerValues.getFirst());
        }
    }

    public static Map<String, DlsRequestHeaderSettings> getDlsRequestHeaderSettings(final Settings settings) {
        final var allowedDlsRequestHeaderSettings = settings.getGroups(OPENSEARCH_SECURITY_DLS_REQUEST_HEADERS_CONFIG);
        return allowedDlsRequestHeaderSettings.values()
            .stream()
            .map(
                s -> new DlsRequestHeaderSettings(
                    s.get("name"),
                    s.getAsBoolean("isMultiValue", false),
                    // by default only match empty values => regex *must* be specified by admin
                    Pattern.compile(s.get("validationRegex", "^$")),
                    s.getAsInt("maxValueLength", 256)
                )
            )
            .collect(Collectors.toUnmodifiableMap(e -> e.name.toLowerCase(), identity()));
    }

    /**
     * Represents the settings for a request header as specified in the config.
     */
    public record DlsRequestHeaderSettings(String name, boolean isMultiValue, Pattern validationPattern, int maxValueLength) {
    }

    /**
     * Represents an actual request header which matched one of the configured DLS request headers.
     * Jackson serialisation is used for the transport between different nodes.
     */
    @JsonTypeInfo(use = JsonTypeInfo.Id.SIMPLE_NAME, include = JsonTypeInfo.As.PROPERTY, property = "class")
    @JsonSubTypes({
        @JsonSubTypes.Type(value = SingleValueDlsRequestHeader.class),
        @JsonSubTypes.Type(value = MultiValueDlsRequestHeader.class), })
    public interface DlsRequestHeader {
        /**
         * @return the name of the request header.
         */
        String name();

        /**
         * @return the header value(s) formatted for usage in a DLS query.
         */
        String serialize();
    }

    public record SingleValueDlsRequestHeader(String name, String value) implements DlsRequestHeader, Serializable {
        @Override
        public String serialize() {
            return this.value;
        }
    }

    public record MultiValueDlsRequestHeader(String name, List<String> values) implements DlsRequestHeader, Serializable {
        @Override
        public String serialize() {
            return values.parallelStream().map(s -> "\"" + s + "\"").collect(Collectors.joining(","));
        }
    }
}
