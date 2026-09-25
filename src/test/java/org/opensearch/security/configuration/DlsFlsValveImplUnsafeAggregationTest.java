/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.configuration;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.core.action.ActionListener;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.bucket.filter.FilterAggregationBuilder;
import org.opensearch.search.aggregations.bucket.global.GlobalAggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.DateHistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.MultiTermsAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.search.aggregations.metrics.AvgAggregationBuilder;
import org.opensearch.search.aggregations.metrics.SumAggregationBuilder;
import org.opensearch.search.aggregations.support.MultiTermsValuesSourceConfig;

import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for DlsFlsValveImpl.containsUnsafeDlsAggregation().
 * Uses reflection to test the private method directly.
 */
public class DlsFlsValveImplUnsafeAggregationTest {

    private Method containsUnsafeDlsAggregation;

    @Before
    public void setUp() throws Exception {
        containsUnsafeDlsAggregation = DlsFlsValveImpl.class.getDeclaredMethod(
            "containsUnsafeDlsAggregation",
            Collection.class,
            ActionListener.class
        );
        containsUnsafeDlsAggregation.setAccessible(true);
    }

    @SuppressWarnings("unchecked")
    private boolean invokeMethod(DlsFlsValveImpl instance, Collection<AggregationBuilder> aggregations, ActionListener<?> listener)
        throws Exception {
        return (boolean) containsUnsafeDlsAggregation.invoke(instance, aggregations, listener);
    }

    /**
     * We need a DlsFlsValveImpl instance to invoke the private method on.
     * Since containsUnsafeDlsAggregation doesn't use any instance state, we use null-safe construction via mock.
     * However, since the method only operates on its parameters, we can use any instance.
     * We'll use reflection to create a minimal instance.
     */
    private DlsFlsValveImpl createMinimalInstance() throws Exception {
        // The method is purely functional (no instance state used), so we can use Mockito to create a partial mock
        // But since DlsFlsValveImpl has a complex constructor, we'll use Unsafe or just test via a subclass approach.
        // Actually, since the method only uses its parameters and no instance fields, we can use any trick to get an instance.
        // Let's use sun.misc.Unsafe to allocate without calling constructor.
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        Object unsafe = unsafeField.get(null);
        Method allocateInstance = unsafeClass.getMethod("allocateInstance", Class.class);
        return (DlsFlsValveImpl) allocateInstance.invoke(unsafe, DlsFlsValveImpl.class);
    }

    // --- Top-level aggregation tests ---

    @Test
    public void testGlobalAggregationAtTopLevel_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        GlobalAggregationBuilder globalAgg = new GlobalAggregationBuilder("my_global");
        List<AggregationBuilder> aggregations = List.of(globalAgg);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("global aggregations are not supported when DLS is activated"));
    }

    @Test
    public void testTermsAggregationWithMinDocCountZero_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        TermsAggregationBuilder termsAgg = new TermsAggregationBuilder("my_terms").field("field1").minDocCount(0);
        List<AggregationBuilder> aggregations = List.of(termsAgg);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("min_doc_count 0 is not supported when DLS is activated"));
    }

    @Test
    public void testMultiTermsAggregationWithMinDocCountZero_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        MultiTermsAggregationBuilder multiTermsAgg = new MultiTermsAggregationBuilder("my_multi_terms").terms(
            Arrays.asList(
                new MultiTermsValuesSourceConfig.Builder().setFieldName("field1").build(),
                new MultiTermsValuesSourceConfig.Builder().setFieldName("field2").build()
            )
        ).minDocCount(0);
        List<AggregationBuilder> aggregations = List.of(multiTermsAgg);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("min_doc_count 0 is not supported when DLS is activated"));
    }

    @Test
    public void testTermsAggregationWithDefaultMinDocCount_shouldBeAllowed() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        TermsAggregationBuilder termsAgg = new TermsAggregationBuilder("my_terms").field("field1");
        List<AggregationBuilder> aggregations = List.of(termsAgg);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(false));
        verify(listener, never()).onFailure(org.mockito.ArgumentMatchers.any());
    }

    @Test
    public void testTermsAggregationWithMinDocCountOne_shouldBeAllowed() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        TermsAggregationBuilder termsAgg = new TermsAggregationBuilder("my_terms").field("field1").minDocCount(1);
        List<AggregationBuilder> aggregations = List.of(termsAgg);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(false));
        verify(listener, never()).onFailure(org.mockito.ArgumentMatchers.any());
    }

    @Test
    public void testSafeAggregations_shouldBeAllowed() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        List<AggregationBuilder> aggregations = List.of(
            new SumAggregationBuilder("my_sum").field("amount"),
            new AvgAggregationBuilder("my_avg").field("amount"),
            new DateHistogramAggregationBuilder("my_date_hist").field("timestamp")
        );

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(false));
        verify(listener, never()).onFailure(org.mockito.ArgumentMatchers.any());
    }

    @Test
    public void testEmptyAggregations_shouldBeAllowed() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        List<AggregationBuilder> aggregations = List.of();

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(false));
        verify(listener, never()).onFailure(org.mockito.ArgumentMatchers.any());
    }

    // --- Nested (sub-aggregation) tests ---

    @Test
    public void testGlobalAggregationNestedUnderFilter_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        FilterAggregationBuilder filterAgg = new FilterAggregationBuilder(
            "my_filter",
            org.opensearch.index.query.QueryBuilders.matchAllQuery()
        );
        filterAgg.subAggregation(new GlobalAggregationBuilder("nested_global"));
        List<AggregationBuilder> aggregations = List.of(filterAgg);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("global aggregations are not supported when DLS is activated"));
    }

    @Test
    public void testTermsWithMinDocCountZeroNestedUnderDateHistogram_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        DateHistogramAggregationBuilder dateHistAgg = new DateHistogramAggregationBuilder("my_date_hist").field("timestamp");
        dateHistAgg.subAggregation(new TermsAggregationBuilder("nested_terms").field("category").minDocCount(0));
        List<AggregationBuilder> aggregations = List.of(dateHistAgg);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("min_doc_count 0 is not supported when DLS is activated"));
    }

    @Test
    public void testMultiTermsWithMinDocCountZeroNestedUnderTerms_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        TermsAggregationBuilder outerTerms = new TermsAggregationBuilder("outer_terms").field("department");
        outerTerms.subAggregation(
            new MultiTermsAggregationBuilder("nested_multi_terms").terms(
                Arrays.asList(
                    new MultiTermsValuesSourceConfig.Builder().setFieldName("field1").build(),
                    new MultiTermsValuesSourceConfig.Builder().setFieldName("field2").build()
                )
            ).minDocCount(0)
        );
        List<AggregationBuilder> aggregations = List.of(outerTerms);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("min_doc_count 0 is not supported when DLS is activated"));
    }

    @Test
    public void testDeeplyNestedUnsafeAggregation_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        // Build: date_histogram -> terms (safe) -> terms (min_doc_count=0)
        TermsAggregationBuilder innerUnsafe = new TermsAggregationBuilder("inner_unsafe").field("category").minDocCount(0);
        TermsAggregationBuilder middleTerms = new TermsAggregationBuilder("middle_terms").field("department");
        middleTerms.subAggregation(innerUnsafe);
        DateHistogramAggregationBuilder outerDateHist = new DateHistogramAggregationBuilder("outer_date_hist").field("timestamp");
        outerDateHist.subAggregation(middleTerms);

        List<AggregationBuilder> aggregations = List.of(outerDateHist);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("min_doc_count 0 is not supported when DLS is activated"));
    }

    @Test
    public void testSafeNestedAggregations_shouldBeAllowed() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        // Build: terms (default min_doc_count) -> sum + avg
        TermsAggregationBuilder termsAgg = new TermsAggregationBuilder("my_terms").field("department");
        termsAgg.subAggregation(new SumAggregationBuilder("nested_sum").field("amount"));
        termsAgg.subAggregation(new AvgAggregationBuilder("nested_avg").field("amount"));

        List<AggregationBuilder> aggregations = List.of(termsAgg);

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(false));
        verify(listener, never()).onFailure(org.mockito.ArgumentMatchers.any());
    }

    // --- Mixed aggregation tests ---

    @Test
    public void testMixedSafeAndUnsafe_shouldBlockOnFirstUnsafe() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        List<AggregationBuilder> aggregations = List.of(
            new SumAggregationBuilder("safe_sum").field("amount"),
            new GlobalAggregationBuilder("unsafe_global"),
            new TermsAggregationBuilder("another_terms").field("field1").minDocCount(0)
        );

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(true));
        // Should fail on the first unsafe aggregation encountered (global)
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("global aggregations are not supported when DLS is activated"));
    }
}
