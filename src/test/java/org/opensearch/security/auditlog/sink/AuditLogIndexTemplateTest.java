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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.transport.client.Client;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.in;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuditLogIndexTemplate}.
 */
public class AuditLogIndexTemplateTest {

    private static final String NAME = "security-auditlog";

    /**
     * SHA-256 of the normalized mappings (see {@link #normalizedMappingsHash()}) for each version of the index
     * template. Clusters only replace an index template with a lower version, so changing the mappings without a new
     * version would never reach them. When you change index_template_mappings.json, raise
     * {@link AuditLogIndexTemplate#VERSION} and ADD an entry for the new version. Do not edit existing entries.
     */
    private static final Map<Long, String> MAPPINGS_HASH_BY_VERSION = Map.of(
        1L,
        "1a390a01c47525ce20e07164d67792476dfe6ac0dc7b1fa887062c0a3dca5522"
    );

    @Mock
    private Client client;
    @Mock
    private Metadata metadata;
    @Mock
    private ActionFuture<AcknowledgedResponse> putTemplateFuture;

    private AuditLogIndexTemplate template;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        when(metadata.templatesV2()).thenReturn(Map.of());
        doReturn(new AcknowledgedResponse(true)).when(putTemplateFuture).actionGet();
        doReturn(putTemplateFuture).when(client).execute(eq(PutComposableIndexTemplateAction.INSTANCE), any());
        template = new AuditLogIndexTemplate(
            NAME,
            List.of("security-auditlog-*"),
            null,
            null,
            AuditLogIndexTemplate.loadMappings(),
            client
        );
    }

    private PutComposableIndexTemplateAction.Request capturePutTemplateRequest() {
        ArgumentCaptor<PutComposableIndexTemplateAction.Request> captor = ArgumentCaptor.forClass(
            PutComposableIndexTemplateAction.Request.class
        );
        verify(client).execute(eq(PutComposableIndexTemplateAction.INSTANCE), captor.capture());
        return captor.getValue();
    }

    @Test
    public void derivesPatternFromQuotedPrefix() {
        assertThat(AuditLogIndexTemplate.indexPatternsFor("'security-auditlog-'YYYY.MM.dd", true), contains("security-auditlog-*"));
        assertThat(AuditLogIndexTemplate.indexPatternsFor("'audit'YYYY.MM", true), contains("audit*"));
    }

    @Test
    public void derivesExactNameForIndexWithoutDateFields() {
        assertThat(AuditLogIndexTemplate.indexPatternsFor("'myaudit'", true), contains("myaudit"));
        assertThat(AuditLogIndexTemplate.indexPatternsFor("security-audit-write-alias", false), contains("security-audit-write-alias"));
    }

    @Test
    public void derivesNoPatternWhenIndexDoesNotStartWithQuotedText() {
        assertThat(AuditLogIndexTemplate.indexPatternsFor("YYYY.MM.dd'-audit'", true), is(empty()));
    }

    @Test
    public void derivesNoPatternWhenIndexNameContainsWildcard() {
        assertThat(AuditLogIndexTemplate.indexPatternsFor("'audit-*-'YYYY.MM.dd", true), is(empty()));
        assertThat(AuditLogIndexTemplate.indexPatternsFor("'audit-?'YYYY.MM.dd", true), is(empty()));
        assertThat(AuditLogIndexTemplate.indexPatternsFor("'audit*'", true), is(empty()));
        assertThat(AuditLogIndexTemplate.indexPatternsFor("audit-*", false), is(empty()));
    }

    @Test
    public void nameDependsOnSinkName() {
        assertThat(AuditLogIndexTemplate.nameForSink("default"), is("security-auditlog"));
        assertThat(AuditLogIndexTemplate.nameForSink("archive"), is("security-auditlog-archive"));
    }

    @Test
    public void createsTemplateWithMappingsAndVersion() throws Exception {
        assertThat(template.ensureExists(metadata), is(true));

        PutComposableIndexTemplateAction.Request request = capturePutTemplateRequest();
        ComposableIndexTemplate created = request.indexTemplate();
        assertThat(request.name(), is(NAME));
        assertThat(created.indexPatterns(), contains("security-auditlog-*"));
        assertThat(created.version(), is(AuditLogIndexTemplate.VERSION));
        assertThat(created.getDataStreamTemplate(), is(nullValue()));
        Map<?, ?> mappings = new ObjectMapper().readValue(created.template().mappings().string(), Map.class);
        assertThat(mappings.get("dynamic"), is(true));
        assertThat(
            ((Map<?, ?>) mappings.get("properties")).get("audit_request_remote_address"),
            is(Map.of("type", "ip", "ignore_malformed", true))
        );
    }

    @Test
    public void createsDataStreamTemplate() {
        new AuditLogIndexTemplate(
            NAME,
            List.of("opensearch-security-auditlog"),
            null,
            new ComposableIndexTemplate.DataStreamTemplate(),
            AuditLogIndexTemplate.loadMappings(),
            client
        ).ensureExists(metadata);

        assertThat(capturePutTemplateRequest().indexTemplate().getDataStreamTemplate(), is(notNullValue()));
    }

    @Test
    public void keepsExistingTemplateWithSameOrNewerVersion() {
        ComposableIndexTemplate existing = mock(ComposableIndexTemplate.class);
        when(existing.version()).thenReturn(AuditLogIndexTemplate.VERSION);
        when(metadata.templatesV2()).thenReturn(Map.of(NAME, existing));

        assertThat(template.ensureExists(metadata), is(true));

        verify(client, never()).execute(eq(PutComposableIndexTemplateAction.INSTANCE), any());
    }

    @Test
    public void replacesExistingTemplateWithoutVersion() {
        ComposableIndexTemplate existing = mock(ComposableIndexTemplate.class);
        when(existing.version()).thenReturn(null);
        when(metadata.templatesV2()).thenReturn(Map.of(NAME, existing));

        assertThat(template.ensureExists(metadata), is(true));

        capturePutTemplateRequest();
    }

    @Test
    public void reportsFailureWhenTemplateCannotBeCreated() {
        doThrow(new IllegalArgumentException("overlapping template with the same priority")).when(putTemplateFuture).actionGet();

        assertThat(template.ensureExists(metadata), is(false));
    }

    @Test
    public void reportsFailureWhenCreationIsNotAcknowledged() {
        doReturn(new AcknowledgedResponse(false)).when(putTemplateFuture).actionGet();

        assertThat(template.ensureExists(metadata), is(false));
    }

    @Test
    public void triesAgainOnNextCall() {
        doThrow(new IllegalArgumentException("overlapping template with the same priority")).when(putTemplateFuture).actionGet();

        template.ensureExists(metadata);
        template.ensureExists(metadata);

        verify(client, times(2)).execute(eq(PutComposableIndexTemplateAction.INSTANCE), any());
    }

    /** Hash of the mappings that ignores whitespace and the order of keys, so only real changes alter it. */
    private static String normalizedMappingsHash() throws Exception {
        final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        final String normalized = mapper.writeValueAsString(mapper.readValue(AuditLogIndexTemplate.loadMappings(), Map.class));
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(normalized.getBytes(StandardCharsets.UTF_8)));
    }

    /** Fails if the mappings changed without a new template version, because clusters would never receive the change. */
    @Test
    public void mappingsChangeRequiresNewVersion() throws Exception {
        final String recorded = MAPPINGS_HASH_BY_VERSION.get(AuditLogIndexTemplate.VERSION);

        assertThat(
            "No mappings hash is recorded for AuditLogIndexTemplate.VERSION="
                + AuditLogIndexTemplate.VERSION
                + ". Add an entry to MAPPINGS_HASH_BY_VERSION with hash "
                + normalizedMappingsHash(),
            recorded,
            is(notNullValue())
        );
        assertThat(
            "index_template_mappings.json changed but AuditLogIndexTemplate.VERSION="
                + AuditLogIndexTemplate.VERSION
                + " did not. Raise VERSION and add an entry to MAPPINGS_HASH_BY_VERSION for the new version with hash "
                + normalizedMappingsHash()
                + ". Do not edit the existing entries.",
            normalizedMappingsHash(),
            is(recorded)
        );
    }

    /** Guards against typos: every mapped field must be a field that {@link AuditMessage} writes. */
    @Test
    public void mappedFieldsAreAuditMessageFields() throws Exception {
        Set<String> auditFields = new HashSet<>();
        for (Field field : AuditMessage.class.getFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                auditFields.add((String) field.get(null));
            }
        }

        Map<?, ?> mappings = new ObjectMapper().readValue(AuditLogIndexTemplate.loadMappings(), Map.class);

        Set<String> mappedFields = new HashSet<>();
        ((Map<?, ?>) mappings.get("properties")).keySet().forEach(key -> mappedFields.add((String) key));
        assertThat(mappings.get("dynamic"), is(true));
        assertThat(mappedFields, everyItem(is(in(auditFields))));
    }
}
