/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.util.Collection;

import org.opensearch.action.DocRequest;

/**
 * A transport request that operates on more than one shareable resource of a single type.
 *
 * <p>{@link DocRequest} names one document, so the resource-access evaluator skips a request whose
 * {@code id()} is blank. A request implementing this interface reports its ids through {@link #ids()}
 * instead, and the evaluator authorizes each of them: the request is allowed only if the user holds
 * the requested action on every id.
 *
 * <p>All ids must be of the type returned by {@link DocRequest#type()} and live in the index returned
 * by {@link DocRequest#index()}. A request carrying ids of more than one type cannot be evaluated this
 * way and should be split.
 *
 * <p>A collection that is empty, or that contains a null or empty id, is not evaluated: the request
 * falls through to the regular privileges evaluator, as a blank {@code id()} does today. A plugin
 * whose request means "all resources" therefore still filters its own results.
 */
public interface MultiResourceRequest extends DocRequest {

    /**
     * The ids of the resources this request operates on.
     *
     * @return the resource ids; must be non-empty and free of blank entries to be evaluated
     */
    Collection<String> ids();

    /**
     * Unused for a multi-resource request, since {@link #ids()} carries the ids. Implementations need
     * not override this.
     *
     * @return {@code null}
     */
    @Override
    default String id() {
        return null;
    }
}
