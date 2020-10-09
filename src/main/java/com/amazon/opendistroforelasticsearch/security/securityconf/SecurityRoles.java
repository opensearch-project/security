/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.Map;
import java.util.Set;

import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;

import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.user.User;

public interface SecurityRoles {

    boolean impliesClusterPermissionPermission(String action0);

    Set<String> getRoleNames();

    Set<String> reduce(Resolved requestedResolved, User user, String[] strings, IndexNameExpressionResolver resolver, ClusterService clusterService);

    boolean impliesTypePermGlobal(Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver, ClusterService clusterService);

    boolean get(Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver, ClusterService clusterService);

    Map<String, Set<String>> getMaskedFields(User user, IndexNameExpressionResolver resolver, ClusterService clusterService);

    Tuple<Map<String, Set<String>>, Map<String, Set<String>>> getDlsFls(User user, IndexNameExpressionResolver resolver, ClusterService clusterService);

    Set<String> getAllPermittedIndicesForKibana(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs);

    SecurityRoles filter(Set<String> roles);

}
