/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.securityconf;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

import java.util.List;
import java.util.Set;

public interface IndexPattern {
    IndexPattern addFlsFields(List<String> flsFields);

    IndexPattern addMaskedFields(List<String> maskedFields);

    WildcardMatcher getPerms();

    Set<String> getStringPerm();

    WildcardMatcher getNonWildCardPerms();

    String getDlsQuery(User user);

    Set<String> concreteIndexNames(User user, IndexNameExpressionResolver resolver, ClusterService cs);

    Set<String> getFls();

    Set<String> getMaskedFields();

    boolean hasDlsQuery();

    boolean hasFlsFields();

    boolean hasMaskedFields();

    String getUnresolvedIndexPattern(User user);

    Set<String> attemptResolveIndexNames(User user, IndexNameExpressionResolver resolver, ClusterService cs);

    Set<String> getResolvedIndexPattern(User user, IndexNameExpressionResolver resolver, ClusterService cs);

    Set<TypePerm> getTypePerms();
}
