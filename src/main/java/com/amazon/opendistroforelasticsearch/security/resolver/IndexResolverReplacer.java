/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.resolver;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.IndicesRequest.Replaceable;
import org.elasticsearch.action.OriginalIndices;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetRequest.Item;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.main.MainRequest;
import org.elasticsearch.action.search.ClearScrollRequest;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchScrollRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.support.nodes.BaseNodesRequest;
import org.elasticsearch.action.support.replication.ReplicationRequest;
import org.elasticsearch.action.support.single.shard.SingleShardRequest;
import org.elasticsearch.action.termvectors.MultiTermVectorsRequest;
import org.elasticsearch.action.termvectors.TermVectorsRequest;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.index.reindex.ReindexRequest;
import org.elasticsearch.snapshots.SnapshotInfo;
import org.elasticsearch.snapshots.SnapshotUtils;
import org.elasticsearch.transport.RemoteClusterService;
import org.elasticsearch.transport.TransportRequest;
import org.greenrobot.eventbus.Subscribe;

import com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigModel;
import com.amazon.opendistroforelasticsearch.security.support.SnapshotRestoreHelper;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import static org.elasticsearch.cluster.metadata.IndexAbstraction.Type.ALIAS;

public class IndexResolverReplacer {

    private static final Set<String> NULL_SET = new HashSet<>(Collections.singleton(null));
    private final Logger log = LogManager.getLogger(this.getClass());
    private final IndexNameExpressionResolver resolver;
    private final ClusterService clusterService;
    private final ClusterInfoHolder clusterInfoHolder;
    private volatile boolean respectRequestIndicesOptions = false;

    public IndexResolverReplacer(IndexNameExpressionResolver resolver, ClusterService clusterService, ClusterInfoHolder clusterInfoHolder) {
        this.resolver = resolver;
        this.clusterService = clusterService;
        this.clusterInfoHolder = clusterInfoHolder;
    }

    private static final boolean isAllWithNoRemote(final String... requestedPatterns) {

        final List<String> patterns = requestedPatterns==null?null:Arrays.asList(requestedPatterns);

        if(IndexNameExpressionResolver.isAllIndices(patterns)) {
            return true;
        }

        if(patterns.size() == 1 && patterns.contains("*")) {
            return true;
        }

        if(new HashSet<String>(patterns).equals(NULL_SET)) {
            return true;
        }

        return false;
    }

    private static final boolean isLocalAll(final String... requestedPatterns) {

        final List<String> patterns = requestedPatterns==null?null:Arrays.asList(requestedPatterns);

        if(IndexNameExpressionResolver.isAllIndices(patterns)) {
            return true;
        }

        if(patterns.contains("_all")) {
            return true;
        }

        if(new HashSet<String>(patterns).equals(NULL_SET)) {
            return true;
        }

        return false;
    }

    private Resolved resolveIndexPatterns(final IndicesOptions indicesOptions, final boolean enableCrossClusterResolution, final String... requestedPatterns0) {

        if(log.isTraceEnabled()) {
            log.trace("resolve requestedPatterns: "+ Arrays.toString(requestedPatterns0));
        }

        if (isAllWithNoRemote(requestedPatterns0)) {
            if (log.isTraceEnabled()) {
                log.trace(Arrays.toString(requestedPatterns0) + " is an ALL pattern without any remote indices");
            }
            return Resolved._LOCAL_ALL;
        }

        Set<String> remoteIndices;
        final List<String> localRequestedPatterns = new ArrayList<>(Arrays.asList(requestedPatterns0));

        final RemoteClusterService remoteClusterService = OpenDistroSecurityPlugin.GuiceHolder.getRemoteClusterService();

        if(remoteClusterService.isCrossClusterSearchEnabled() && enableCrossClusterResolution) {
            remoteIndices = new HashSet<>();
            final Map<String, OriginalIndices> remoteClusterIndices = OpenDistroSecurityPlugin.GuiceHolder.getRemoteClusterService()
                    .groupIndices(indicesOptions, requestedPatterns0, idx -> resolver.hasIndexOrAlias(idx, clusterService.state()));
            final Set<String> remoteClusters = remoteClusterIndices.keySet().stream()
                    .filter(k->!RemoteClusterService.LOCAL_CLUSTER_GROUP_KEY.equals(k)).collect(Collectors.toSet());
            for(String remoteCluster : remoteClusters) {
                for(String remoteIndex : remoteClusterIndices.get(remoteCluster).indices()) {
                    remoteIndices.add(RemoteClusterService.buildRemoteIndexName(remoteCluster, remoteIndex));
                }
            }

            final Iterator<String> iterator = localRequestedPatterns.iterator();
            while (iterator.hasNext()) {
                final String[] split = iterator.next().split(String.valueOf(RemoteClusterService.REMOTE_CLUSTER_INDEX_SEPARATOR), 2);
                final WildcardMatcher matcher = WildcardMatcher.from(split[0]);
                if (split.length > 1 && matcher.matchAny(remoteClusters)) {
                    iterator.remove();
                }
            }

            if (log.isTraceEnabled()) {
                log.trace("CCS is enabled, we found this local patterns " + localRequestedPatterns + " and this remote patterns: " + remoteIndices);
            }

        } else {
            remoteIndices = Collections.emptySet();
        }

        final Set<String> matchingAliases;
        Set<String> matchingAllIndices;

        if (isLocalAll(requestedPatterns0)) {
            if (log.isTraceEnabled()) {
                log.trace(Arrays.toString(requestedPatterns0) + " is an LOCAL ALL pattern");
            }
            matchingAliases = Resolved.All_SET;
            matchingAllIndices = Resolved.All_SET;

        } else if (!remoteIndices.isEmpty() && localRequestedPatterns.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace(Arrays.toString(requestedPatterns0) + " is an LOCAL EMPTY request");
            }
            matchingAllIndices = Collections.emptySet();
            matchingAliases = Collections.emptySet();
        }

        else {
            final ClusterState state = clusterService.state();
            final Set<String> dateResolvedLocalRequestedPatterns = localRequestedPatterns
                            .stream()
                            .map(resolver::resolveDateMathExpression)
                            .collect(Collectors.toSet());
            final WildcardMatcher dateResolvedMatcher = WildcardMatcher.from(dateResolvedLocalRequestedPatterns);
            //fill matchingAliases
            final Map<String, IndexAbstraction> lookup = state.metadata().getIndicesLookup();
            matchingAliases = lookup.entrySet()
                    .stream()
                    .filter(e -> e.getValue().getType() == ALIAS)
                    .map(Map.Entry::getKey)
                    .filter(dateResolvedMatcher)
                    .collect(Collectors.toSet());

            try {
                matchingAllIndices = new HashSet<>(Arrays.asList(
                        resolver.concreteIndexNames(state, indicesOptions, localRequestedPatterns.toArray(new String[0]))
                ));
                if (log.isDebugEnabled()) {
                    log.debug("Resolved pattern {} to {}", localRequestedPatterns, matchingAllIndices);
                }
            } catch (IndexNotFoundException e1) {
                if (log.isDebugEnabled()) {
                    log.debug("No such indices for pattern {}, use raw value", localRequestedPatterns);
                }

                matchingAllIndices = dateResolvedLocalRequestedPatterns;
            }
        }

        return new Resolved(matchingAliases, matchingAllIndices, new HashSet<>(Arrays.asList(requestedPatterns0)), remoteIndices);

    }



    //dnfof
    public boolean replace(final TransportRequest request, boolean retainMode, String... replacements) {
        return getOrReplaceAllIndices(request, new IndicesProvider() {

            @Override
            public String[] provide(String[] original, Object request, boolean supportsReplace) {
                if(supportsReplace) {
                    if(retainMode && !isAllWithNoRemote(original)) {
                        final Resolved resolved = resolveRequest(request);
                        final List<String> retained = WildcardMatcher.from(resolved.getAllIndices()).getMatchAny(replacements, Collectors.toList());
                        retained.addAll(resolved.getRemoteIndices());
                        return retained.toArray(new String[0]);
                    }
                    return replacements;
                } else {
                    return NOOP;
                }
            }
        }, false);
    }

    private static final class IndexResolveKey {
        private final IndicesOptions opts;
        private final boolean enableCrossClusterResolution;
        private final String[] original;
        public IndexResolveKey(IndicesOptions opts, boolean enableCrossClusterResolution, String[] original) {
            this.opts = opts;
            this.enableCrossClusterResolution = enableCrossClusterResolution;
            this.original = original;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            IndexResolveKey that = (IndexResolveKey) o;
            return enableCrossClusterResolution == that.enableCrossClusterResolution &&
                    opts.equals(that.opts) &&
                    Arrays.equals(original, that.original);
        }

        @Override
        public int hashCode() {
            return Boolean.hashCode(enableCrossClusterResolution) + 31 * opts.hashCode() + 127*Arrays.hashCode(original);
        }
    }

    public Resolved resolveRequest(final Object request) {
        if(log.isDebugEnabled()) {
            log.debug("Resolve aliases, indices and types from {}", request.getClass().getSimpleName());
        }

        final Resolved.Builder resolvedBuilder = new Resolved.Builder();
        final AtomicBoolean isIndicesRequest = new AtomicBoolean();
        // set of previously resolved index requests to avoid resolving
        // the same index more than once while processing bulk requests
        final Set<IndexResolveKey> alreadyResolved = new HashSet<>();

        getOrReplaceAllIndices(request, (original, localRequest, supportsReplace) -> {
            final IndicesOptions indicesOptions = indicesOptionsFrom(localRequest);
            final boolean enableCrossClusterResolution = localRequest instanceof FieldCapabilitiesRequest || localRequest instanceof SearchRequest;
            final IndexResolveKey key = new IndexResolveKey(indicesOptions, enableCrossClusterResolution, original);
            // skip the whole thing if we have seen this exact resolveIndexPatterns request
            if (!alreadyResolved.contains(key)) {
                final Resolved iResolved = resolveIndexPatterns(key.opts, key.enableCrossClusterResolution, key.original);
                alreadyResolved.add(key);
                resolvedBuilder.add(iResolved);
                isIndicesRequest.set(true);

                if (log.isTraceEnabled()) {
                    log.trace("Resolved patterns {} for {} ({}) to {}", original, localRequest.getClass().getSimpleName(), request.getClass().getSimpleName(), iResolved);
                }
            }
            return IndicesProvider.NOOP;
        }, false);

        if(!isIndicesRequest.get()) {
            //not an indices request
            return Resolved._LOCAL_ALL;
        }

        if(log.isTraceEnabled()) {
            log.trace("Finally resolved for {}: {}", request.getClass().getSimpleName(), resolvedBuilder.build());
        }

        return resolvedBuilder.build();
    }

    public final static class Resolved implements Serializable, Writeable {

        /**
         *
         */
        private static final Set<String> All_SET = Collections.singleton("*");
        private static final long serialVersionUID = 1L;
        public final static Resolved _LOCAL_ALL = new Resolved(All_SET, All_SET, All_SET, Collections.emptySet());
        private final Set<String> aliases;
        private final Set<String> allIndices;
        private static final Set<String> types = ImmutableSet.of("*");

        private final Set<String> originalRequested;
        private final Set<String> remoteIndices;

        private Resolved(final Set<String> aliases, final Set<String> allIndices,
                         final Set<String> originalRequested, final Set<String> remoteIndices) {
            this.aliases = aliases;
            this.allIndices = allIndices;
            this.originalRequested = originalRequested;
            this.remoteIndices = remoteIndices;
        }

        public boolean isLocalAll() {
            if(IndexResolverReplacer.isLocalAll(originalRequested==null?null:originalRequested.toArray(new String[0]))) {
                return true;
            }

            return aliases.contains("*") && allIndices.contains("*") && types.contains("*");
        }

        public Set<String> getAliases() {
            return Collections.unmodifiableSet(aliases);
        }

        public Set<String> getAllIndices() {
            return Collections.unmodifiableSet(allIndices);
        }

        public Set<String> getTypes() {
            return types;
        }

        public Set<String> getOriginalRequested() {
            return Collections.unmodifiableSet(originalRequested);
        }

        public Set<String> getRemoteIndices() {
            return Collections.unmodifiableSet(remoteIndices);
        }

        @Override
        public String toString() {
            return "Resolved [aliases=" + aliases + ", allIndices=" + allIndices + ", types=" + types
                    + ", originalRequested=" + originalRequested + ", remoteIndices=" + remoteIndices + "]";
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((aliases == null) ? 0 : aliases.hashCode());
            result = prime * result + ((allIndices == null) ? 0 : allIndices.hashCode());
            result = prime * result + ((originalRequested == null) ? 0 : originalRequested.hashCode());
            result = prime * result + ((remoteIndices == null) ? 0 : remoteIndices.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            Resolved other = (Resolved) obj;
            if (aliases == null) {
                if (other.aliases != null)
                    return false;
            } else if (!aliases.equals(other.aliases))
                return false;
            if (allIndices == null) {
                if (other.allIndices != null)
                    return false;
            } else if (!allIndices.equals(other.allIndices))
                return false;
            if (originalRequested == null) {
                if (other.originalRequested != null)
                    return false;
            } else if (!originalRequested.equals(other.originalRequested))
                return false;
            if (remoteIndices == null) {
                if (other.remoteIndices != null)
                    return false;
            } else if (!remoteIndices.equals(other.remoteIndices))
                return false;
            return true;
        }


        private static class Builder {

            private final Set<String> aliases = new HashSet<String>();
            private final Set<String> allIndices = new HashSet<String>();
            private final Set<String> originalRequested = new HashSet<String>();
            private final Set<String> remoteIndices = new HashSet<String>();

            public Builder() {
                this(null, null, null, null);
            }

            public Builder(Collection<String> aliases, Collection<String> allIndices,
                           String[] originalRequested, Collection<String> remoteIndices) {

                if(aliases != null) {
                    this.aliases.addAll(aliases);
                }


                if(allIndices != null) {
                    this.allIndices.addAll(allIndices);
                }

                if(originalRequested != null) {
                    this.originalRequested.addAll(Arrays.asList(originalRequested));
                }

                if(remoteIndices != null) {
                    this.remoteIndices.addAll(remoteIndices);
                }
            }

            public Builder add(Resolved r) {
                this.aliases.addAll(r.aliases);
                this.allIndices.addAll(r.allIndices);
                this.originalRequested.addAll(r.originalRequested);
                this.remoteIndices.addAll(r.remoteIndices);
                return this;
            }
            
            public Builder addOriginalRequested(List<String> originalRequested) {
                if(originalRequested != null) {
                    this.originalRequested.addAll(originalRequested);
                }
                return this;
            }
            
            public Builder addRemoteIndices(Set<String> remoteIndices) {
                if(remoteIndices != null) {
                    this.remoteIndices.addAll(remoteIndices);
                }
                return this;
            }

            public Resolved build() {
                return new Resolved(aliases, allIndices, originalRequested, remoteIndices);
            }
        }

        public Resolved(final StreamInput in) throws IOException {
            aliases = new HashSet<String>(in.readList(StreamInput::readString));
            allIndices = new HashSet<String>(in.readList(StreamInput::readString));
            originalRequested = new HashSet<String>(in.readList(StreamInput::readString));
            remoteIndices = new HashSet<String>(in.readList(StreamInput::readString));
        }


        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeStringCollection(new ArrayList<>(aliases));
            out.writeStringCollection(new ArrayList<>(allIndices));
            out.writeStringCollection(new ArrayList<>(originalRequested));
            out.writeStringCollection(new ArrayList<>(remoteIndices));
        }
    }

    private List<String> renamedIndices(final RestoreSnapshotRequest request, final List<String> filteredIndices) {
        try {
            final List<String> renamedIndices = new ArrayList<>();
            for (final String index : filteredIndices) {
                String renamedIndex = index;
                if (request.renameReplacement() != null && request.renamePattern() != null) {
                    renamedIndex = index.replaceAll(request.renamePattern(), request.renameReplacement());
                }
                renamedIndices.add(renamedIndex);
            }
            return renamedIndices;
        } catch (PatternSyntaxException e) {
            log.error("Unable to parse the regular expression denoted in 'rename_pattern'. Please correct the pattern an try again.");
            throw e;
        }
    }


    //--

    @FunctionalInterface
    public interface IndicesProvider {
        public static final String[] NOOP = new String[0];
        String[] provide(String[] original, Object request, boolean supportsReplace);
    }

    private boolean checkIndices(Object request, String[] indices, boolean needsToBeSizeOne, boolean allowEmpty) {

        if(indices == IndicesProvider.NOOP) {
            return false;
        }

        if(!allowEmpty && (indices == null || indices.length == 0)) {
            if(log.isTraceEnabled() && request != null) {
                log.trace("Null or empty indices for "+request.getClass().getName());
            }
            return false;
        }

        if(!allowEmpty && needsToBeSizeOne && indices.length != 1) {
            if(log.isTraceEnabled() && request != null) {
                log.trace("To much indices for "+request.getClass().getName());
            }
            return false;
        }

        for (int i = 0; i < indices.length; i++) {
            final String index = indices[i];
            if(index == null || index.isEmpty()) {
                //not allowed
                if(log.isTraceEnabled() && request != null) {
                    log.trace("At least one null or empty index for "+request.getClass().getName());
                }
                return false;
            }
        }

        return true;
    }

    /**
     * new
     * @param request
     * @param allowEmptyIndices
     * @return
     */
    @SuppressWarnings("rawtypes")
    private boolean getOrReplaceAllIndices(final Object request, final IndicesProvider provider, boolean allowEmptyIndices) {

        if(log.isTraceEnabled()) {
            log.trace("getOrReplaceAllIndices() for "+request.getClass());
        }

        boolean result = true;

        if (request instanceof BulkRequest) {

            for (DocWriteRequest ar : ((BulkRequest) request).requests()) {
                result = getOrReplaceAllIndices(ar, provider, false) && result;
            }

        } else if (request instanceof MultiGetRequest) {

            for (ListIterator<Item> it = ((MultiGetRequest) request).getItems().listIterator(); it.hasNext();){
                Item item = it.next();
                result = getOrReplaceAllIndices(item, provider, false) && result;
                /*if(item.index() == null || item.indices() == null || item.indices().length == 0) {
                    it.remove();
                }*/
            }

        } else if (request instanceof MultiSearchRequest) {

            for (ListIterator<SearchRequest> it = ((MultiSearchRequest) request).requests().listIterator(); it.hasNext();) {
                SearchRequest ar = it.next();
                result = getOrReplaceAllIndices(ar, provider, false) && result;
                /*if(ar.indices() == null || ar.indices().length == 0) {
                    it.remove();
                }*/
            }

        } else if (request instanceof MultiTermVectorsRequest) {

            for (ActionRequest ar : (Iterable<TermVectorsRequest>) () -> ((MultiTermVectorsRequest) request).iterator()) {
                result = getOrReplaceAllIndices(ar, provider, false) && result;
            }

        } else if(request instanceof PutMappingRequest) {
            PutMappingRequest pmr = (PutMappingRequest) request;
            Index concreteIndex = pmr.getConcreteIndex();
            if(concreteIndex != null && (pmr.indices() == null || pmr.indices().length == 0)) {
                String[] newIndices = provider.provide(new String[]{concreteIndex.getName()}, request, true);
                if(checkIndices(request, newIndices, true, allowEmptyIndices) == false) {
                    return false;
                }

                ((PutMappingRequest) request).indices(newIndices);
                ((PutMappingRequest) request).setConcreteIndex(null);
            } else {
                String[] newIndices = provider.provide(((PutMappingRequest) request).indices(), request, true);
                if(checkIndices(request, newIndices, false, allowEmptyIndices) == false) {
                    return false;
                }
                ((PutMappingRequest) request).indices(newIndices);
            }
        } else if(request instanceof RestoreSnapshotRequest) {

                if(clusterInfoHolder.isLocalNodeElectedMaster() == Boolean.FALSE) {
                    return true;
                }

                final RestoreSnapshotRequest restoreRequest = (RestoreSnapshotRequest) request;
                final SnapshotInfo snapshotInfo = SnapshotRestoreHelper.getSnapshotInfo(restoreRequest);

                if (snapshotInfo == null) {
                    log.warn("snapshot repository '" + restoreRequest.repository() + "', snapshot '" + restoreRequest.snapshot() + "' not found");
                    provider.provide(new String[]{"*"}, request, false);
                } else {
                    final List<String> requestedResolvedIndices = SnapshotUtils.filterIndices(snapshotInfo.indices(), restoreRequest.indices(), restoreRequest.indicesOptions());
                    final List<String> renamedTargetIndices = renamedIndices(restoreRequest, requestedResolvedIndices);
                    //final Set<String> indices = new HashSet<>(requestedResolvedIndices);
                    //indices.addAll(renamedTargetIndices);
                    if(log.isDebugEnabled()) {
                        log.debug("snapshot: {} contains this indices: {}", snapshotInfo.snapshotId().getName(), renamedTargetIndices);
                    }
                    provider.provide(renamedTargetIndices.toArray(new String[0]), request, false);
            }

        } else if (request instanceof IndicesAliasesRequest) {
            for(AliasActions ar: ((IndicesAliasesRequest) request).getAliasActions()) {
                result = getOrReplaceAllIndices(ar, provider, false) && result;
            }
        } else if (request instanceof DeleteRequest) {
            String[] newIndices = provider.provide(((DeleteRequest) request).indices(), request, true);
            if(checkIndices(request, newIndices, true, allowEmptyIndices) == false) {
                return false;
            }
            ((DeleteRequest) request).index(newIndices.length!=1?null:newIndices[0]);
        } else if (request instanceof UpdateRequest) {
            String[] newIndices = provider.provide(((UpdateRequest) request).indices(), request, true);
            if(checkIndices(request, newIndices, true, allowEmptyIndices) == false) {
                return false;
            }
            ((UpdateRequest) request).index(newIndices.length!=1?null:newIndices[0]);
        } else if (request instanceof SingleShardRequest) {
            final SingleShardRequest<?> gr = (SingleShardRequest<?>) request;
            final String[] indices = gr.indices();
            final String index = gr.index();

            final List<String> indicesL = new ArrayList<String>();

            if (index != null) {
                indicesL.add(index);
            }

            if (indices != null && indices.length > 0) {
                indicesL.addAll(Arrays.asList(indices));
            }

            String[] newIndices = provider.provide(indicesL.toArray(new String[0]), request, true);
            if(checkIndices(request, newIndices, true, allowEmptyIndices) == false) {
                return false;
            }
            ((SingleShardRequest) request).index(newIndices.length!=1?null:newIndices[0]);
        } else if (request instanceof IndexRequest) {
            String[] newIndices = provider.provide(((IndexRequest) request).indices(), request, true);
            if(checkIndices(request, newIndices, true, allowEmptyIndices) == false) {
                return false;
            }
            ((IndexRequest) request).index(newIndices.length!=1?null:newIndices[0]);
        } else if (request instanceof Replaceable) {
            String[] newIndices = provider.provide(((Replaceable) request).indices(), request, true);
            if(checkIndices(request, newIndices, false, allowEmptyIndices) == false) {
                return false;
            }
            ((Replaceable) request).indices(newIndices);
        } else if (request instanceof BulkShardRequest) {
            provider.provide(((ReplicationRequest) request).indices(), request, false);
            //replace not supported?
        } else if (request instanceof ReplicationRequest) {
            String[] newIndices = provider.provide(((ReplicationRequest) request).indices(), request, true);
            if(checkIndices(request, newIndices, true, allowEmptyIndices) == false) {
                return false;
            }
            ((ReplicationRequest) request).index(newIndices.length!=1?null:newIndices[0]);
        } else if (request instanceof MultiGetRequest.Item) {
            String[] newIndices = provider.provide(((MultiGetRequest.Item) request).indices(), request, true);
            if(checkIndices(request, newIndices, true, allowEmptyIndices) == false) {
                return false;
            }
            ((MultiGetRequest.Item) request).index(newIndices.length!=1?null:newIndices[0]);
        } else if (request instanceof CreateIndexRequest) {
            String[] newIndices = provider.provide(((CreateIndexRequest) request).indices(), request, true);
            if(checkIndices(request, newIndices, true, allowEmptyIndices) == false) {
                return false;
            }
            ((CreateIndexRequest) request).index(newIndices.length!=1?null:newIndices[0]);
        } else if (request instanceof ReindexRequest) {
            result = getOrReplaceAllIndices(((ReindexRequest) request).getDestination(), provider, false) && result;
            result = getOrReplaceAllIndices(((ReindexRequest) request).getSearchRequest(), provider, false) && result;
        } else if (request instanceof BaseNodesRequest) {
            //do nothing
        } else if (request instanceof MainRequest) {
            //do nothing
        } else if (request instanceof ClearScrollRequest) {
            //do nothing
        } else if (request instanceof SearchScrollRequest) {
            //do nothing
        } else {
            if(log.isDebugEnabled()) {
                log.debug(request.getClass() + " not supported (It is likely not a indices related request)");
            }
            result = false;
        }

        return result;
    }

    private IndicesOptions indicesOptionsFrom(Object localRequest) {
        
        if(!respectRequestIndicesOptions) {
            return IndicesOptions.fromOptions(false, true, true, false);
        }

        if (IndicesRequest.class.isInstance(localRequest)) {
            return ((IndicesRequest) localRequest).indicesOptions();
        }
        else if (RestoreSnapshotRequest.class.isInstance(localRequest)) {
            return ((RestoreSnapshotRequest) localRequest).indicesOptions();
        }
        else {
            return IndicesOptions.fromOptions(false, true, true, false);
        }
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        respectRequestIndicesOptions = dcm.isRespectRequestIndicesEnabled();
    }
}