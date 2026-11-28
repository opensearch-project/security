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

package org.opensearch.security.auditlog.sink;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.settings.Settings;
import org.opensearch.transport.client.Client;

/**
 * Index template with explicit mappings for audit log indices, created by the internal OpenSearch audit log sinks.
 *
 * <p>Fields that are not mapped explicitly are still mapped dynamically. The index template is only created if the
 * operator enabled it, so a failure to create it is reported to the caller, like a failure to create an index.</p>
 */
final class AuditLogIndexTemplate {

    private static final Logger log = LogManager.getLogger(AuditLogIndexTemplate.class);

    /** Classpath location of the mappings of the index template. */
    static final String MAPPINGS_RESOURCE = "/auditlog/index_template_mappings.json";
    /**
     * Version of the index template. Increase it when the mappings change, so that clusters with an older template get
     * the new one. A template with the same or a newer version is left untouched.
     */
    static final long VERSION = 1L;

    /** A leading quoted literal of a Joda date pattern, followed by the rest of the pattern. */
    private static final Pattern QUOTED_PREFIX = Pattern.compile("^'([^']+)'(.*)$");

    private final String name;
    private final List<String> indexPatterns;
    private final Settings settings;
    private final ComposableIndexTemplate.DataStreamTemplate dataStreamTemplate;
    private final String mappings;
    private final Client client;

    /**
     * @param name               name of the index template
     * @param indexPatterns      index patterns the index template applies to
     * @param settings           index settings of the index template, or {@code null}
     * @param dataStreamTemplate data stream configuration of the index template, or {@code null} for regular indices
     * @param mappings           mappings of the index template, see {@link #loadMappings()}
     */
    AuditLogIndexTemplate(
        final String name,
        final List<String> indexPatterns,
        final Settings settings,
        final ComposableIndexTemplate.DataStreamTemplate dataStreamTemplate,
        final String mappings,
        final Client client
    ) {
        this.name = name;
        this.indexPatterns = List.copyOf(indexPatterns);
        this.settings = settings;
        this.dataStreamTemplate = dataStreamTemplate;
        this.mappings = mappings;
        this.client = client;
    }

    /** Name of the index template of a sink, so that several sinks do not overwrite each other's index template. */
    static String nameForSink(final String sinkName) {
        return "default".equals(sinkName) ? "security-auditlog" : "security-auditlog-" + sinkName;
    }

    /**
     * Derives the index patterns of the index template from the index setting of a sink.
     *
     * <p>The index setting is a Joda date pattern, in which literal text is enclosed in single quotes. The leading
     * quoted text becomes the prefix of the pattern, for example {@code 'security-auditlog-'YYYY.MM.dd} becomes
     * {@code security-auditlog-*}. A setting that is not a date pattern, or is only quoted text, names a single index,
     * which is matched exactly.</p>
     *
     * @param index         the index setting
     * @param isDatePattern whether the index setting is a valid date pattern
     * @return the index patterns, or an empty list if the setting is a date pattern that does not start with quoted
     * text, as the pattern would then match every index, or if the index name contains a wildcard, as it could then
     * match other indices. Index names cannot contain wildcards, so such a setting does not work anyway.
     */
    static List<String> indexPatternsFor(final String index, final boolean isDatePattern) {
        if (!isDatePattern) {
            return containsWildcard(index) ? List.of() : List.of(index);
        }
        final Matcher matcher = QUOTED_PREFIX.matcher(index);
        if (!matcher.matches()) {
            return List.of();
        }
        final String prefix = matcher.group(1);
        if (containsWildcard(prefix)) {
            return List.of();
        }
        return List.of(matcher.group(2).isEmpty() ? prefix : prefix + "*");
    }

    private static boolean containsWildcard(final String indexName) {
        return indexName.indexOf('*') >= 0 || indexName.indexOf('?') >= 0;
    }

    /** Reads the mappings of the index template, or returns {@code null} if they cannot be read. */
    static String loadMappings() {
        try (InputStream in = AuditLogIndexTemplate.class.getResourceAsStream(MAPPINGS_RESOURCE)) {
            if (in == null) {
                log.error("Audit log index template mappings {} not found. The index template is not created.", MAPPINGS_RESOURCE);
                return null;
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("Unable to read audit log index template mappings {}. The index template is not created.", MAPPINGS_RESOURCE, e);
            return null;
        }
    }

    String name() {
        return name;
    }

    List<String> indexPatterns() {
        return indexPatterns;
    }

    /**
     * Creates or updates the index template, unless a template with the same name and the same or a newer version
     * already exists.
     *
     * @return {@code true} if the index template exists, {@code false} if it could not be created
     */
    boolean ensureExists(final Metadata metadata) {
        final ComposableIndexTemplate existing = metadata.templatesV2().get(name);
        if (existing != null && existing.version() != null && existing.version() >= VERSION) {
            return true;
        }

        try {
            final ComposableIndexTemplate template = new ComposableIndexTemplate(
                indexPatterns,
                new Template(settings, new CompressedXContent(mappings), null),
                null,
                null,
                VERSION,
                null,
                dataStreamTemplate
            );
            final PutComposableIndexTemplateAction.Request request = new PutComposableIndexTemplateAction.Request(name).indexTemplate(
                template
            ).cause("security audit log");
            final AcknowledgedResponse response = client.execute(PutComposableIndexTemplateAction.INSTANCE, request).actionGet();
            if (response.isAcknowledged()) {
                log.info("Created audit log index template '{}' for index patterns {}", name, indexPatterns);
                return true;
            }
            log.error("Failed to create audit log index template '{}'. Template creation was not acknowledged.", name);
            return false;
        } catch (Exception e) {
            log.error(
                "Unable to create audit log index template '{}' for index patterns {}. If another index template matches these"
                    + " patterns with the same priority, remove it or change its priority.",
                name,
                indexPatterns,
                e
            );
            return false;
        }
    }
}
