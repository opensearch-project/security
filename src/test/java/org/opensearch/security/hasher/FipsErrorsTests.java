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

package org.opensearch.security.hasher;

import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;

public class FipsErrorsTests {

    @Test
    public void classNameMatchesFqcnAndSimpleName() {
        assertThat(
            FipsErrors.isFipsUnapprovedOperationErrorClassName(FipsErrors.FIPS_UNAPPROVED_OPERATION_ERROR),
            is(true)
        );
        assertThat(FipsErrors.isFipsUnapprovedOperationErrorClassName("FipsUnapprovedOperationError"), is(true));
        assertThat(
            FipsErrors.isFipsUnapprovedOperationErrorClassName("com.example.shaded.FipsUnapprovedOperationError"),
            is(true)
        );
        assertThat(FipsErrors.isFipsUnapprovedOperationErrorClassName("java.lang.Error"), is(false));
        assertThat(FipsErrors.isFipsUnapprovedOperationErrorClassName(null), is(false));
        assertThat(FipsErrors.isFipsUnapprovedOperationErrorClassName(""), is(false));
    }

    @Test
    public void ignoresOrdinaryErrors() {
        assertThat(FipsErrors.isFipsUnapprovedOperationError(new Error("boom")), is(false));
        assertThat(FipsErrors.isFipsUnapprovedOperationError(new OutOfMemoryError()), is(false));
        assertThat(FipsErrors.isFipsUnapprovedOperationError(new RuntimeException("not an error")), is(false));
        assertThat(FipsErrors.isFipsUnapprovedOperationError(null), is(false));
    }

    @Test
    public void detectsTestDoubleBySimpleClassName() {
        assertThat(FipsErrors.isFipsUnapprovedOperationError(new FipsUnapprovedOperationError("short password")), is(true));
    }

    @Test
    public void convertsFipsErrorToSecurityException() {
        FipsUnapprovedOperationError fips = new FipsUnapprovedOperationError("password too short");
        OpenSearchSecurityException converted = FipsErrors.asSecurityExceptionOrPropagate(fips);
        assertThat(converted, instanceOf(OpenSearchSecurityException.class));
        assertThat(converted.getMessage(), is("password rejected by FIPS policy"));
        assertThat(converted.getCause(), sameInstance(fips));
    }

    @Test
    public void propagatesNonFipsError() {
        Error oom = new OutOfMemoryError("heap");
        Error thrown = assertThrows(OutOfMemoryError.class, () -> FipsErrors.asSecurityExceptionOrPropagate(oom));
        assertThat(thrown, sameInstance(oom));
    }

    @Test
    public void detectsFipsErrorWrappedAsCause() {
        RuntimeException wrapped = new RuntimeException("wrapper", new FipsUnapprovedOperationError("nested"));
        assertThat(FipsErrors.isFipsUnapprovedOperationError(wrapped), is(true));
    }
}
