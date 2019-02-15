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
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
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
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.elasticsearch.action.get.GetRequest;
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
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.index.reindex.ReindexRequest;
import org.elasticsearch.snapshots.SnapshotInfo;
import org.elasticsearch.snapshots.SnapshotUtils;
import org.elasticsearch.transport.RemoteClusterAware;
import org.elasticsearch.transport.RemoteClusterService;
import org.elasticsearch.transport.TransportRequest;

import com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.support.SnapshotRestoreHelper;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.google.common.collect.Sets;

public final class IndexResolverReplacer {

    //private final static IndicesOptions DEFAULT_INDICES_OPTIONS = IndicesOptions.lenientExpandOpen();
    //private static final String[] NO_INDICES_SET = Sets.newHashSet("\\",";",",","/","|").toArray(new String[0]);
    private static final Set<String> NULL_SET = Sets.newHashSet((String)null);
    private final Map<Class<?>, Method> typeCache = Collections.synchronizedMap(new HashMap<Class<?>, Method>(100));
    private final Map<Class<?>, Method> typesCache = Collections.synchronizedMap(new HashMap<Class<?>, Method>(100));
    private final Logger log = LogManager.getLogger(this.getClass());
    private final IndexNameExpressionResolver resolver;
    private final ClusterService clusterService;
    private final ClusterInfoHolder clusterInfoHolder;

    public IndexResolverReplacer(IndexNameExpressionResolver resolver, ClusterService clusterService, ClusterInfoHolder clusterInfoHolder) {
        super();
        this.resolver = resolver;
        this.clusterService = clusterService;
        this.clusterInfoHolder = clusterInfoHolder;
    }

    public static final boolean isAll(final String... requestedPatterns) {

        final List<String> patterns = requestedPatterns==null?null:Arrays.asList(requestedPatterns);

        if(IndexNameExpressionResolver.isAllIndices(patterns)) {
            return true;
        }

        if(patterns.contains("*")) {
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

    private Resolved resolveIndexPatterns(final String... requestedPatterns) {

        if(log.isTraceEnabled()) {
            log.trace("resolve requestedPatterns: "+Arrays.toString(requestedPatterns));
        }
        
       if(isAll(requestedPatterns)) {
           return Resolved._ALL;
       }

       ClusterState state = clusterService.state();

       final SortedMap<String, AliasOrIndex> lookup = state.metaData().getAliasAndIndexLookup();
       final Set<String> aliases = lookup.entrySet().stream().filter(e->e.getValue().isAlias()).map(e->e.getKey()).collect(Collectors.toSet());

       final Set<String> matchingAliases = new HashSet<>(requestedPatterns.length*10);
       final Set<String> matchingIndices = new HashSet<>(requestedPatterns.length*10);
       final Set<String> matchingAllIndices = new HashSet<>(requestedPatterns.length*10);

       //fill matchingAliases
       for (int i = 0; i < requestedPatterns.length; i++) {
           final String requestedPattern = resolver.resolveDateMathExpression(requestedPatterns[i]);
           final List<String> _aliases = WildcardMatcher.getMatchAny(requestedPattern, aliases);
           matchingAliases.addAll(_aliases);
       }


       //-alias not possible

        {
            //final String requestedPattern = resolver.resolveDateMathExpression(requestedPatterns[i]);
            //final List<String> _aliases = WildcardMatcher.getMatchAny(requestedPattern, aliases);
            //matchingAliases.addAll(_aliases);

            List<String> _indices;
            try {
                _indices = new ArrayList<>(Arrays.asList(resolver.concreteIndexNames(state, IndicesOptions.fromOptions(false, true, true, false), requestedPatterns)));
                if (log.isDebugEnabled()) {
                    log.debug("Resolved pattern {} to {}", requestedPatterns, _indices);
                }
            } catch (IndexNotFoundException e1) {
                if (log.isDebugEnabled()) {
                    log.debug("No such indices for pattern {}, use raw value", (Object[]) requestedPatterns);
                }

                _indices = new ArrayList<>(requestedPatterns.length);

                for (int i = 0; i < requestedPatterns.length; i++) {
                    String requestedPattern = requestedPatterns[i];
                    _indices.add(resolver.resolveDateMathExpression(requestedPattern));
                }

                /*if(requestedPatterns.length == 1) {
                    _indices = Collections.singletonList(resolver.resolveDateMathExpression(requestedPatterns[0]));
                } else {
                    log.warn("Multiple ({}) index patterns {} cannot be resolved, assume _all", requestedPatterns.length, requestedPatterns);
                    //_indices = Collections.singletonList("*");
                    _indices = Arrays.asList(requestedPatterns); //date math not handled
                }*/

            }

            final List<String> _aliases = WildcardMatcher.getMatchAny(requestedPatterns, aliases);

            matchingAllIndices.addAll(_indices);

           if(_aliases.isEmpty()) {
               matchingIndices.addAll(_indices); //date math resolved?
           } else {

               if(!_indices.isEmpty()) {

                   for(String al:_aliases) {
                       Set<String> doubleIndices = lookup.get(al).getIndices().stream().map(a->a.getIndex().getName()).collect(Collectors.toSet());
                       _indices.removeAll(doubleIndices);
                   }

                   matchingIndices.addAll(_indices);
               }
           }
       }
       return new Resolved.Builder(matchingAliases, matchingIndices, matchingAllIndices, null).build();

    }

    @SuppressWarnings("rawtypes")
    private Set<String> resolveTypes(final Object request) {
        // check if type security is enabled
        final Class<?> requestClass = request.getClass();
        final Set<String> requestTypes = new HashSet<String>();

        if (true) {
            if (request instanceof BulkShardRequest) {
                BulkShardRequest bsr = (BulkShardRequest) request;
                for (BulkItemRequest bir : bsr.items()) {
                    requestTypes.add(bir.request().type());
                }
            } else if (request instanceof DocWriteRequest) {
                requestTypes.add(((DocWriteRequest) request).type());
            } else if (request instanceof SearchRequest) {
                requestTypes.addAll(Arrays.asList(((SearchRequest) request).types()));
            } else if (request instanceof GetRequest) {
                requestTypes.add(((GetRequest) request).type());
            } else {

                Method typeMethod = null;
                if (typeCache.containsKey(requestClass)) {
                    typeMethod = typeCache.get(requestClass);
                } else {
                    try {
                        typeMethod = requestClass.getMethod("type");
                        typeCache.put(requestClass, typeMethod);
                    } catch (NoSuchMethodException e) {
                        typeCache.put(requestClass, null);
                    } catch (SecurityException e) {
                        log.error("Cannot evaluate type() for {} due to {}", requestClass, e, e);
                    }

                }

                Method typesMethod = null;
                if (typesCache.containsKey(requestClass)) {
                    typesMethod = typesCache.get(requestClass);
                } else {
                    try {
                        typesMethod = requestClass.getMethod("types");
                        typesCache.put(requestClass, typesMethod);
                    } catch (NoSuchMethodException e) {
                        typesCache.put(requestClass, null);
                    } catch (SecurityException e) {
                        log.error("Cannot evaluate types() for {} due to {}", requestClass, e, e);
                    }

                }

                if (typeMethod != null) {
                    try {
                        String type = (String) typeMethod.invoke(request);
                        if (type != null) {
                            requestTypes.add(type);
                        }
                    } catch (Exception e) {
                        log.error("Unable to invoke type() for {} due to", requestClass, e);
                    }
                }

                if (typesMethod != null) {
                    try {
                        final String[] types = (String[]) typesMethod.invoke(request);

                        if (types != null) {
                            requestTypes.addAll(Arrays.asList(types));
                        }
                    } catch (Exception e) {
                        log.error("Unable to invoke types() for {} due to", requestClass, e);
                    }
                }
            }

        }

        if (log.isTraceEnabled()) {
            log.trace("requestTypes {} for {}", requestTypes, request.getClass());
        }

        return Collections.unmodifiableSet(requestTypes);
    }

    /*public boolean exclude(final TransportRequest request, String... exclude) {
        return getOrReplaceAllIndices(request, new IndicesProvider() {

            @Override
            public String[] provide(final String[] original, final Object request, final boolean supportsReplace) {
                if(supportsReplace) {
                    
                    final List<String> result = new ArrayList<String>(Arrays.asList(original));
                    
//                    if(isAll(original)) {
//                        result = new ArrayList<String>(Collections.singletonList("*"));
//                    } else {
//                        result = new ArrayList<String>(Arrays.asList(original));
//                    }
                    
                    
                    
                    final Set<String> preliminary = new HashSet<>(resolveIndexPatterns(result.toArray(new String[0])).allIndices);      
                    
                    if(log.isTraceEnabled()) {
                        log.trace("resolved original {}, excludes {}",preliminary, Arrays.toString(exclude));
                    }
                    
                    WildcardMatcher.wildcardRetainInSet(preliminary, exclude);      
                    
                    if(log.isTraceEnabled()) {
                        log.trace("modified original {}",preliminary);
                    }
                    
                    result.addAll(preliminary.stream().map(a->"-"+a).collect(Collectors.toList()));

                    if(log.isTraceEnabled()) {
                        log.trace("exclude for {}: replaced {} with {}", request.getClass().getSimpleName(), Arrays.toString(original) ,result);
                    }
                    
                    return result.toArray(new String[0]);
                } else {
                    return NOOP;
                }
            }
        }, false);
    }*/

    //dnfof
    public boolean replace(final TransportRequest request, boolean retainMode, String... replacements) {
        return getOrReplaceAllIndices(request, new IndicesProvider() {

            @Override
            public String[] provide(String[] original, Object request, boolean supportsReplace) {
                if(supportsReplace) {
                    if(retainMode && original != null && original.length > 0) {
                        //TODO datemath?
                        List<String> originalAsList = Arrays.asList(original);
                        if(originalAsList.contains("*") || originalAsList.contains("_all")) {
                            return replacements;
                        }
                        
                        original = resolver.concreteIndexNames(clusterService.state(), IndicesOptions.lenientExpandOpen(), original);
                        
                        final String[] retained = WildcardMatcher.getMatchAny(original, replacements).toArray(new String[0]);
                        return retained;
                    }
                    return replacements;
                } else {
                    return NOOP;
                }
            }
        }, false);
    }

    public Resolved resolveRequest(final Object request) {
        if(log.isDebugEnabled()) {
            log.debug("Resolve aliases, indices and types from {}", request.getClass().getSimpleName());
        }
        Resolved.Builder resolvedBuilder = new Resolved.Builder();
        final AtomicBoolean returnEmpty = new AtomicBoolean();
        getOrReplaceAllIndices(request, new IndicesProvider() {

            @Override
            public String[] provide(String[] original, Object localRequest, boolean supportsReplace) {

                //CCS
                if((localRequest instanceof FieldCapabilitiesRequest || localRequest instanceof SearchRequest)
                        && (request instanceof FieldCapabilitiesRequest || request instanceof SearchRequest)) {
                    assert supportsReplace: localRequest.getClass().getName()+" does not support replace";
                    final Tuple<Boolean, String[]> ccsResult = handleCcs((Replaceable) localRequest);
                    if(ccsResult.v1() == Boolean.TRUE) {
                        if(ccsResult.v2() == null || ccsResult.v2().length == 0) {
                            returnEmpty.set(true);
                        }
                        original = ccsResult.v2();
                    }

                }
                if(returnEmpty.get()) {

                    if(log.isTraceEnabled()) {
                        log.trace("CCS return empty indices for local node");
                    }

                } else {
                    final Resolved iResolved = resolveIndexPatterns(original);

                    if(log.isTraceEnabled()) {
                        log.trace("Resolved patterns {} for {} ({}) to {}", original, localRequest.getClass().getSimpleName(), request.getClass().getSimpleName(), iResolved);
                    }

                    resolvedBuilder.add(iResolved);
                    resolvedBuilder.addTypes(resolveTypes(localRequest));

                }

                return IndicesProvider.NOOP;
            }
        }, false);

        if(log.isTraceEnabled()) {
            log.trace("Finally resolved for {}: {}", request.getClass().getSimpleName(), resolvedBuilder.build());
        }

        if(returnEmpty.get()) {
            return Resolved._EMPTY;
        }

        return resolvedBuilder.build();
    }


    private Tuple<Boolean, String[]> handleCcs(final IndicesRequest.Replaceable request) {

        Boolean modified = Boolean.FALSE;
        String[] localIndices = request.indices();
        
        final RemoteClusterService remoteClusterService = OpenDistroSecurityPlugin.GuiceHolder.getRemoteClusterService();

        // handle CCS
        // TODO how to handle aliases with CCS??
        if (remoteClusterService.isCrossClusterSearchEnabled() && (request instanceof FieldCapabilitiesRequest || request instanceof SearchRequest)) {
            IndicesRequest.Replaceable searchRequest = request;
            final Map<String, OriginalIndices> remoteClusterIndices = OpenDistroSecurityPlugin.GuiceHolder.getRemoteClusterService().groupIndices(
                    searchRequest.indicesOptions(), searchRequest.indices(), idx -> resolver.hasIndexOrAlias(idx, clusterService.state()));

            assert remoteClusterIndices.size() > 0:"Remote cluster size must not be zero";
            
            // check permissions?
            if (log.isDebugEnabled()) {
                log.debug("CCS case, original indices: " + Arrays.toString(localIndices));
                log.debug("remoteClusterIndices ({}): {}", remoteClusterIndices.size(), remoteClusterIndices);
            }

            final OriginalIndices originalLocalIndices = remoteClusterIndices.get(RemoteClusterAware.LOCAL_CLUSTER_GROUP_KEY);
            
            if(originalLocalIndices == null) {
            	localIndices = null;
            } else {
            	localIndices = originalLocalIndices.indices();
            }

            modified = Boolean.TRUE;

            if (log.isDebugEnabled()) {
                log.debug("remoteClusterIndices keys" + remoteClusterIndices.keySet() + "//remoteClusterIndices "
                        + remoteClusterIndices);
                log.debug("modified local indices: " + Arrays.toString(localIndices));
            }
        }

        return new Tuple<Boolean, String[]>(modified, localIndices);

    }

    public final static class Resolved implements Serializable, Writeable {

        /**
         *
         */
        private static final Set<String> All_SET = Sets.newHashSet("*");
        private static final long serialVersionUID = 1L;
        public final static Resolved _ALL = new Resolved(All_SET, All_SET, All_SET, All_SET);
        public final static Resolved _EMPTY = new Builder().build();

        private final Set<String> aliases;
        private final Set<String> indices;
        private final Set<String> allIndices;
        private final Set<String> types;

        private Resolved(final Set<String> aliases, final Set<String> indices, final Set<String> allIndices, final Set<String> types) {
            super();
            this.aliases = aliases;
            this.indices = indices;
            this.allIndices = allIndices;
            this.types = types;

            if(!aliases.isEmpty() || !indices.isEmpty() || !allIndices.isEmpty()) {
                if(types.isEmpty()) {
                    throw new ElasticsearchException("Empty types for nonempty inidices or aliases");
                }
            }
        }

        public boolean isAll() {
            return aliases.contains("*") && indices.contains("*") && allIndices.contains("*") && types.contains("*");
        }

        public boolean isEmpty() {
            return aliases.isEmpty() && indices.isEmpty() && allIndices.isEmpty() && types.isEmpty();
        }

        public Set<String> getAliases() {
            return Collections.unmodifiableSet(aliases);
        }

        public Set<String> getIndices() {
            return Collections.unmodifiableSet(indices);
        }

        public Set<String> getAllIndices() {
            return Collections.unmodifiableSet(allIndices);
        }

        public Set<String> getTypes() {
            return Collections.unmodifiableSet(types);
        }

        //TODO equals and hashcode??

        @Override
        public String toString() {
            return "Resolved [aliases=" + aliases + ", indices=" + indices + ", allIndices=" + allIndices + ", types=" + types
                    + ", isAll()=" + isAll() + ", isEmpty()=" + isEmpty() + "]";
        }



        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((aliases == null) ? 0 : aliases.hashCode());
            result = prime * result + ((allIndices == null) ? 0 : allIndices.hashCode());
            result = prime * result + ((indices == null) ? 0 : indices.hashCode());
            result = prime * result + ((types == null) ? 0 : types.hashCode());
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
            if (indices == null) {
                if (other.indices != null)
                    return false;
            } else if (!indices.equals(other.indices))
                return false;
            if (types == null) {
                if (other.types != null)
                    return false;
            } else if (!types.equals(other.types))
                return false;
            return true;
        }



        private static class Builder {

            final Set<String> aliases = new HashSet<String>();
            final Set<String> indices = new HashSet<String>();
            final Set<String> allIndices = new HashSet<String>();
            final Set<String> types = new HashSet<String>();

            public Builder() {
                this(null, null, null, null);
            }

            public Builder(Collection<String> aliases, Collection<String> indices, Collection<String> allIndices, Collection<String> types) {

                if(aliases != null) {
                    this.aliases.addAll(aliases);
                }

                if(indices != null) {
                    this.indices.addAll(indices);
                }

                if(allIndices != null) {
                    this.allIndices.addAll(allIndices);
                }

                if(types != null) {
                    this.types.addAll(types);
                }
            }

            public Builder addTypes(Collection<String> types) {
                if(types != null && types.size() > 0) {
                    if(this.types.contains("*")) {
                        this.types.remove("*");
                    }
                    this.types.addAll(types);
                }
                return this;
            }

            public Builder add(Resolved r) {

                this.aliases.addAll(r.aliases);
                this.indices.addAll(r.indices);
                this.allIndices.addAll(r.allIndices);
                addTypes(r.types);
                return this;
            }

            public Resolved build() {
                if(types.isEmpty()) {
                    types.add("*");
                }

                return new Resolved(new HashSet<String>(aliases), new HashSet<String>(indices), new HashSet<String>(allIndices), new HashSet<String>(types));
            }
        }

        public Resolved(final StreamInput in) throws IOException {
            aliases = new HashSet<String>(in.readList(StreamInput::readString));
            indices = new HashSet<String>(in.readList(StreamInput::readString));
            allIndices = new HashSet<String>(in.readList(StreamInput::readString));
            types = new HashSet<String>(in.readList(StreamInput::readString));
        }


        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeStringList(new ArrayList<>(aliases));
            out.writeStringList(new ArrayList<>(indices));
            out.writeStringList(new ArrayList<>(allIndices));
            out.writeStringList(new ArrayList<>(types));

        }
    }

    private List<String> renamedIndices(final RestoreSnapshotRequest request, final List<String> filteredIndices) {
        final List<String> renamedIndices = new ArrayList<>();
        for (final String index : filteredIndices) {
            String renamedIndex = index;
            if (request.renameReplacement() != null && request.renamePattern() != null) {
                renamedIndex = index.replaceAll(request.renamePattern(), request.renameReplacement());
            }
            renamedIndices.add(renamedIndex);
        }
        return renamedIndices;
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
     * @param newIndices
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
}
