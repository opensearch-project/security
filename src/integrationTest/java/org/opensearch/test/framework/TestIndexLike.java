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

package org.opensearch.test.framework;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

public interface TestIndexLike {
    String name();

    Set<String> documentIds();

    Map<String, TestData.TestDocument> documents();

    default TestIndexLike.Filtered filteredBy(Predicate<TestData.TestDocument> filter) {
        return new Filtered(this, filter);
    }

    default TestIndexLike intersection(TestIndexLike other) {
        if (other == this) {
            return this;
        }

        if (!this.name().equals(other.name())) {
            throw new IllegalArgumentException("Cannot intersect different indices: " + this + " vs " + other);
        }

        if (other instanceof TestIndexLike.Filtered) {
            return ((TestIndexLike.Filtered) other).intersection(this);
        }

        return this;
    }

    class Filtered implements TestIndexLike {
        final TestIndexLike testIndexLike;
        final Predicate<TestData.TestDocument> filter;
        Map<String, TestData.TestDocument> cachedDocuments;

        Filtered(TestIndexLike testIndexLike, Predicate<TestData.TestDocument> filter) {
            this.testIndexLike = testIndexLike;
            this.filter = filter;
        }

        @Override
        public String name() {
            return testIndexLike.name();
        }

        @Override
        public Set<String> documentIds() {
            return documents().keySet();
        }

        @Override
        public Map<String, TestData.TestDocument> documents() {
            Map<String, TestData.TestDocument> result = this.cachedDocuments;

            if (result == null) {
                result = new HashMap<>();

                for (Map.Entry<String, TestData.TestDocument> entry : this.testIndexLike.documents().entrySet()) {
                    if (this.filter.test(entry.getValue())) {
                        result.put(entry.getKey(), entry.getValue());
                    }
                }

                this.cachedDocuments = Collections.unmodifiableMap(result);
            }

            return result;
        }

        @Override
        public TestIndexLike intersection(TestIndexLike other) {
            if (other == this) {
                return this;
            }

            if (other instanceof Filtered) {
                return new Filtered(this.testIndexLike, node -> this.filter.test(node) && ((Filtered) other).filter.test(node));
            } else {
                return this;
            }
        }

        @Override
        public String toString() {
            return testIndexLike + " [filtered]";
        }

    }

}
