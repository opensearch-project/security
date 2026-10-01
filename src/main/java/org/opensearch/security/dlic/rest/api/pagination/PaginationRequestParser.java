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

package org.opensearch.security.dlic.rest.api.pagination;

import org.opensearch.action.pagination.PageParams;
import org.opensearch.action.pagination.PageToken;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.dlic.rest.validation.ValidationResult;

import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;

/**
 * Parses and validates pagination query parameters from an incoming {@link RestRequest}.
 */
public final class PaginationRequestParser {

    public static final String PARAM_SIZE = PageParams.PARAM_SIZE;
    public static final String PARAM_SORT = PageParams.PARAM_SORT;
    public static final String PARAM_NEXT_TOKEN = PageParams.PARAM_NEXT_TOKEN;
    public static final String RESPONSE_NEXT_TOKEN_KEY = PageToken.PAGINATED_RESPONSE_NEXT_TOKEN_KEY;

    private PaginationRequestParser() {}

    public static boolean isPaginationRequested(final RestRequest request) {
        return request.hasParam(PARAM_SIZE) || request.hasParam(PARAM_SORT) || request.hasParam(PARAM_NEXT_TOKEN);
    }

    /**
     * Parses and validates pagination parameters from the request.
     *
     * @param request the incoming REST request
     * @return a successful {@link ValidationResult} with a {@link PaginationParams} instance,
     *         or a {@code 400 Bad Request} error describing what is wrong
     */
    public static ValidationResult<PaginationParams> parse(final RestRequest request) {
        final String sizeParam = request.param(PARAM_SIZE);
        final String sortParam = request.param(PARAM_SORT);
        final String tokenParam = request.param(PARAM_NEXT_TOKEN);

        // Validates sort param
        final String sort;
        if (sortParam == null) {
            sort = PaginationParams.SORT_ASC;
        } else if (PaginationParams.SORT_ASC.equals(sortParam) || PaginationParams.SORT_DESC.equals(sortParam)) {
            sort = sortParam;
        } else {
            return ValidationResult.error(
                RestStatus.BAD_REQUEST,
                badRequestMessage("Invalid sort parameter '" + sortParam + "'. Must be 'asc' or 'desc'.")
            );
        }

        // Validates size param
        final int size;
        if (sizeParam == null) {
            size = PaginationParams.DEFAULT_SIZE;
        } else {
            try {
                size = Integer.parseInt(sizeParam);
            } catch (NumberFormatException e) {
                return ValidationResult.error(
                    RestStatus.BAD_REQUEST,
                    badRequestMessage("Invalid size parameter '" + sizeParam + "'. Must be a positive integer.")
                );
            }
            if (size <= 0 || size > PaginationParams.MAX_SIZE) {
                return ValidationResult.error(
                    RestStatus.BAD_REQUEST,
                    badRequestMessage("Invalid size parameter '" + size + "'. Must be between 1 and " + PaginationParams.MAX_SIZE + ".")
                );
            }
        }

        return ValidationResult.success(new PaginationParams(size, sort, tokenParam));
    }
}
