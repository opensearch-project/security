/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.support;

import java.util.function.Function;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThrows;

public class ReflectiveAttributeAccessorsTest {

    @Test
    public void invokesPublicObjectMethod() {
        Function<MethodTarget, String> accessor = ReflectiveAttributeAccessors.objectMethod("value", String.class);

        assertThat(accessor.apply(new MethodTarget()), is("result"));
    }

    @Test
    public void returnsNullForNullObject() {
        Function<MethodTarget, String> accessor = ReflectiveAttributeAccessors.objectMethod("value", String.class);

        assertThat(accessor.apply(null), nullValue());
    }

    @Test
    public void wrapsMissingObjectMethod() {
        Function<MethodTarget, String> accessor = ReflectiveAttributeAccessors.objectMethod("missing", String.class);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> accessor.apply(new MethodTarget()));

        assertThat(exception.getMessage(), is("Error while invoking missing on " + MethodTarget.class.getName()));
        assertThat(exception.getCause(), instanceOf(NoSuchMethodException.class));
    }

    public static final class MethodTarget {
        public String value() {
            return "result";
        }
    }
}
