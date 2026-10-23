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

    private DlsFlsValveImpl createMinimalInstance() throws Exception {
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        Object unsafe = unsafeField.get(null);
        Method allocateInstance = unsafeClass.getMethod("allocateInstance", Class.class);
        return (DlsFlsValveImpl) allocateInstance.invoke(unsafe, DlsFlsValveImpl.class);
    }

    @Test
    public void testGlobalAggregationAtTopLevel_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        boolean result = invokeMethod(instance, List.of(new GlobalAggregationBuilder("my_global")), listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("global aggregations are not supported when DLS is activated"));
    }

    @Test
    public void testTermsAggregationWithMinDocCountZero_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);

        boolean result = invokeMethod(instance, List.of(new TermsAggregationBuilder("my_terms").field("field1").minDocCount(0)), listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("min_doc_count 0 is not supported when DLS is activated"));
    }

    @Test
    public void testMultiTermsAggregationWithMinDocCountZero_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);
        MultiTermsAggregationBuilder aggregation = new MultiTermsAggregationBuilder("my_multi_terms").terms(
            Arrays.asList(
                new MultiTermsValuesSourceConfig.Builder().setFieldName("field1").build(),
                new MultiTermsValuesSourceConfig.Builder().setFieldName("field2").build()
            )
        ).minDocCount(0);

        boolean result = invokeMethod(instance, List.of(aggregation), listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("min_doc_count 0 is not supported when DLS is activated"));
    }

    @Test
    public void testSafeAggregations_shouldBeAllowed() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);
        List<AggregationBuilder> aggregations = List.of(
            new TermsAggregationBuilder("my_terms").field("field1"),
            new SumAggregationBuilder("my_sum").field("amount"),
            new AvgAggregationBuilder("my_avg").field("amount"),
            new DateHistogramAggregationBuilder("my_date_hist").field("timestamp")
        );

        boolean result = invokeMethod(instance, aggregations, listener);

        assertThat(result, is(false));
        verify(listener, never()).onFailure(org.mockito.ArgumentMatchers.any());
    }

    @Test
    public void testUnsafeNestedAggregations_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);
        FilterAggregationBuilder filterAggregation = new FilterAggregationBuilder(
            "my_filter",
            org.opensearch.index.query.QueryBuilders.matchAllQuery()
        );
        filterAggregation.subAggregation(new GlobalAggregationBuilder("nested_global"));

        boolean result = invokeMethod(instance, List.of(filterAggregation), listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("global aggregations are not supported when DLS is activated"));
    }

    @Test
    public void testDeeplyNestedTermsWithMinDocCountZero_shouldBeBlocked() throws Exception {
        DlsFlsValveImpl instance = createMinimalInstance();
        ActionListener<?> listener = mock(ActionListener.class);
        TermsAggregationBuilder innerUnsafe = new TermsAggregationBuilder("inner_unsafe").field("category").minDocCount(0);
        TermsAggregationBuilder middleTerms = new TermsAggregationBuilder("middle_terms").field("department");
        middleTerms.subAggregation(innerUnsafe);
        DateHistogramAggregationBuilder outerDateHistogram = new DateHistogramAggregationBuilder("outer_date_hist").field("timestamp");
        outerDateHistogram.subAggregation(middleTerms);

        boolean result = invokeMethod(instance, List.of(outerDateHistogram), listener);

        assertThat(result, is(true));
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        assertThat(captor.getValue().getMessage(), containsString("min_doc_count 0 is not supported when DLS is activated"));
    }
}
