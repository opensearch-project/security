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

package com.floragunn.searchguard.configuration;

import java.io.IOException;
import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;

public final class SearchGuardLicense implements Writeable {

    private static final DateTimeFormatter DEFAULT_FOMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    
    private String uid;
    private Type type;
    private Feature[] features;
    private String issueDate;
    private String expiryDate;
    private String issuedTo;
    private String issuer;
    private String startDate;
    private Integer majorVersion;
    private String clusterName;
    private int allowedNodeCount;
    private final List<String> msgs = new ArrayList<>();
    private long expiresInDays = 0;
    private boolean isExpired = true;
    private boolean valid = true;
    private String action;
    private String prodUsage;
    private final ClusterService clusterService;
    
    public static SearchGuardLicense createTrialLicense(String issueDate, ClusterService clusterService, String msg) {
        final SearchGuardLicense trialLicense =  new SearchGuardLicense("00000000-0000-0000-0000-000000000000", Type.TRIAL, Feature.values(), issueDate, addDays(issueDate, 60), "The world", "floragunn GmbH", issueDate, 6, "*", Integer.MAX_VALUE, clusterService);
        if(msg != null) {
            trialLicense.msgs.add(msg);
        }
        return trialLicense;
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(uid);
        out.writeEnum(type);
        out.writeString(issueDate);
        out.writeString(expiryDate);
        out.writeString(issuedTo);
        out.writeString(issuer);
        out.writeString(startDate);
        out.writeOptionalVInt(majorVersion);
        out.writeString(clusterName);
        out.writeInt(allowedNodeCount);
        out.writeStringList(msgs);
        out.writeLong(expiresInDays);
        out.writeBoolean(isExpired);
        out.writeBoolean(valid);
        out.writeString(action);
        out.writeString(prodUsage);
        out.writeArray(StreamOutput::writeEnum, features==null?new Feature[0]:features);
    }
    
    public SearchGuardLicense(final StreamInput in) throws IOException {
        uid = in.readString();
        type = in.readEnum(Type.class);
        issueDate = in.readString();
        expiryDate = in.readString();
        issuedTo = in.readString();
        issuer = in.readString();
        startDate = in.readString();
        majorVersion = in.readOptionalVInt();
        clusterName = in.readString();
        allowedNodeCount = in.readInt();
        msgs.addAll(in.readList(StreamInput::readString));
        expiresInDays = in.readLong();
        isExpired = in.readBoolean();
        valid = in.readBoolean();
        action = in.readString();
        prodUsage = in.readString();
        features = in.readArray(new Reader<Feature>() {

            @Override
            public Feature read(StreamInput in) throws IOException {
                return in.readEnum(Feature.class);
            }}, Feature[]::new);

        clusterService = null;
        
    }

    public SearchGuardLicense(final Map<String, Object> map, ClusterService clusterService) {
        this(
                 (String) (map==null?null:map.get("uid")),
                 (Type)   (map==null?null:Type.valueOf(((String)map.get("type")).toUpperCase())),
                 (map==null?null:parseFeatures((List<String>) map.get("features"))),
                 (String) (map==null?null:map.get("issued_date")),
                 (String) (map==null?null:map.get("expiry_date")),
                 (String) (map==null?null:map.get("issued_to")),
                 (String) (map==null?null:map.get("issuer")),
                 (String) (map==null?null:map.get("start_date")),
                 (Integer)(map==null?null:map.get("major_version")),
                 (String) (map==null?null:map.get("cluster_name")),
                 (Integer) (map==null?0:map.get("allowed_node_count_per_cluster"))    
                 , clusterService
        );
    }
    
    private final static Feature[] parseFeatures(List<String> featuresAsString) {
        if(featuresAsString == null || featuresAsString.isEmpty()) {
            return new Feature[0];
        }
        
        List<Feature> retVal = new ArrayList<SearchGuardLicense.Feature>();
        
        for(String feature: featuresAsString) {
            if(feature != null && !feature.isEmpty()) {
                try {
                    retVal.add(Feature.valueOf(feature.toUpperCase()));
                } catch (Exception e) {
                    //no such feature
                }
            }
            
        }
        
        return retVal.toArray(new Feature[0]);
    }
    
    public SearchGuardLicense(String uid, Type type, Feature[] features, String issueDate, String expiryDate, String issuedTo, String issuer, String startDate, Integer majorVersion, String clusterName, int allowedNodeCount,  ClusterService clusterService) {
        super();
        this.uid = Objects.requireNonNull(uid);
        this.type = Objects.requireNonNull(type);
        this.features = features==null?new Feature[0]:features.clone();
        this.issueDate = Objects.requireNonNull(issueDate);
        this.expiryDate = Objects.requireNonNull(expiryDate);
        this.issuedTo = Objects.requireNonNull(issuedTo);
        this.issuer = Objects.requireNonNull(issuer);
        this.startDate = Objects.requireNonNull(startDate);
        this.majorVersion = Objects.requireNonNull(majorVersion);
        this.clusterName = Objects.requireNonNull(clusterName);
        this.allowedNodeCount = allowedNodeCount;
        this.clusterService = Objects.requireNonNull(clusterService);
        validate();
    }
    
    private void validate() {    
        
        final LocalDate today = LocalDate.now();
        
        if(uid == null || uid.isEmpty()) {
            valid = false;
            msgs.add("'uid' must not be empty or null");
        }
        
        if(type == null) {
            valid = false;
            msgs.add("'type' must not be empty or null");
        }
        
        try {
            final LocalDate isd = parseDate(issueDate);
            
            if(isd.isAfter(today)) {
                valid = false;
                msgs.add("License not valid yet.");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
            valid = false;
            msgs.add("'issued_date' not valid");
        }
        
        try {
            final LocalDate exd = parseDate(expiryDate);
            
            if(exd.isBefore(today)) {
                valid = false;
                msgs.add("License is expired");
            } else {
                isExpired = false;
                expiresInDays = diffDays(exd);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
            valid = false;
            msgs.add("'expiry_date' not valid");
        }
        
        if(issuedTo == null || issuedTo.isEmpty()) {
            valid = false;
            msgs.add("'issued_to' must not be empty or null");
        }
        
        if(issuer == null || issuer.isEmpty()) {
            valid = false;
            msgs.add("'issuer' must not be empty or null");
        }
        
        try {
            UUID.fromString(uid);
        } catch (Exception e) {
            valid = false;
            msgs.add("'uid' not valid");
        }
        
        try {
            parseDate(startDate);
        } catch (Exception e) {
            e.printStackTrace();
            valid = false;
            msgs.add("'start_date' not valid");
        }
        
        if(clusterName == null || clusterName.isEmpty()) {
            valid = false;
            msgs.add("'cluster_name' must not be empty or null");
        } 
        
        final int numberOfNodes = clusterService.state().getNodes().getSize();
        
        if(numberOfNodes > allowedNodeCount) {
            valid = false;
            msgs.add("Only "+allowedNodeCount+" node(s) allowed but you run "+numberOfNodes+" node(s)");
        }
        
        final String nodes = allowedNodeCount > 1500 ?"unlimited":String.valueOf(allowedNodeCount);

        if(!valid) {
            prodUsage = "No, because the license is not valid.";
            action = "Purchase a license. Visit docs.search-guard.com/v6/search-guard-enterprise-edition or write to <sales@floragunn.com>";
        } else {
        	switch (type) {
        		case ACADEMIC:
        			prodUsage = "Yes, unlimited clusters with all commercial features and "+nodes+" nodes per cluster for non-commercial academic and scientific use.";
        			break;
        		case OEM:
        			prodUsage = "Yes, for usage with bundled OEM products. Standalone usage is not permitted.";
        			break;
        		case COMPANY:
        			prodUsage = "Yes, unlimited clusters with all commercial features and "+nodes+" nodes per cluster for usage by '"+issuedTo+"'";
        			break;
        		default:
        			prodUsage = "Yes, one cluster with all commercial features and "+nodes+" nodes per cluster.";
        			break;
        	}            
            action = "";
        }
    }
    
    public enum Type {
        FULL,
        SME,
        SINGLE,
        ACADEMIC,
        OEM,
        TRIAL,
        COMPANY
    }
    
    public enum Feature {
        COMPLIANCE
    }
   
    private static LocalDate parseDate(String date) {
        return LocalDate.parse(date, DEFAULT_FOMATTER);
    }
    
    private static String addDays(String date, int days) {
        final LocalDate d = parseDate(date);
        return DEFAULT_FOMATTER.format(d.plus(Period.ofDays(days)));
    }
    
    private static long diffDays(LocalDate to) {  
        return ChronoUnit.DAYS.between(LocalDate.now(), to);
    }

    public String getUid() {
        return uid;
    }

    public Type getType() {
        return type;
    }

    public String getIssueDate() {
        return issueDate;
    }

    public String getExpiryDate() {
        return expiryDate;
    }

    public String getIssuedTo() {
        return issuedTo;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getStartDate() {
        return startDate;
    }

    public Integer getMajorVersion() {
        return majorVersion;
    }

    public String getClusterName() {
        return clusterName;
    }

    public List<String> getMsgs() {
        return Collections.unmodifiableList(msgs);
    }

    public long getExpiresInDays() {
        return expiresInDays;
    }

    public boolean isExpired() {
        return isExpired;
    }

    public boolean isValid() {
        return valid;
    }

    public String getAction() {
        return action;
    }

    public String getProdUsage() {
        return prodUsage;
    }
    
    public int getAllowedNodeCount() {
        return allowedNodeCount;
    }
    
    public Feature[] getFeatures() {
        return features==null?null:features.clone();
    }
    
    public boolean hasFeature(Feature feature) {
        if(features == null || features.length == 0) {
            return false;
        }
        return Arrays.asList(features).contains(feature);
    }

    @Override
    public String toString() {
        return "SearchGuardLicense [uid=" + uid + ", type=" + type + ", features=" + Arrays.toString(features) + ", issueDate=" + issueDate + ", expiryDate=" + expiryDate
                + ", issuedTo=" + issuedTo + ", issuer=" + issuer + ", startDate=" + startDate + ", majorVersion=" + majorVersion
                + ", clusterName=" + clusterName + ", allowedNodeCount=" + allowedNodeCount + ", msgs=" + msgs + ", expiresInDays="
                + expiresInDays + ", isExpired=" + isExpired + ", valid=" + valid + ", action=" + action + ", prodUsage=" + prodUsage
                + ", clusterService=" + clusterService + ", getMsgs()=" + getMsgs() + ", getExpiresInDays()=" + getExpiresInDays()
                + ", isExpired()=" + isExpired() + ", isValid()=" + isValid() + ", getAction()=" + getAction() + ", getProdUsage()="
                + getProdUsage() + "]";
    }
}
