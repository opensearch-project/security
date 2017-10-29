/*
 * Copyright 2017 floragunn GmbH
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
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;

public final class SearchGuardLicense implements Writeable {

    private String uid;
    private Type type;
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
        final SearchGuardLicense trialLicense =  new SearchGuardLicense("00000000-0000-0000-0000-000000000000", Type.TRIAL, issueDate, addDays(issueDate, 92L), "The world", "floragunn GmbH", issueDate, 6, "*", Integer.MAX_VALUE, clusterService);
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
        clusterService = null;
    }

    public SearchGuardLicense(final Map<String, Object> map, ClusterService clusterService) {
        this(
                 (String) (map==null?null:map.get("uid")),
                 (Type)   (map==null?null:Type.valueOf(((String)map.get("type")).toUpperCase())),
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
    
    public SearchGuardLicense(String uid, Type type, String issueDate, String expiryDate, String issuedTo, String issuer, String startDate, Integer majorVersion, String clusterName, int allowedNodeCount,  ClusterService clusterService) {
        super();
        this.uid = Objects.requireNonNull(uid);
        this.type = Objects.requireNonNull(type);
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
        final Date now = new Date();
        
        if(uid == null || uid.isEmpty()) {
            valid = false;
            msgs.add("'uid' must not be empty or null");
        }
        
        if(type == null) {
            valid = false;
            msgs.add("'type' must not be empty or null");
        }
        
        try {
            Date isd = parseDate(issueDate);
            
            if(isd.after(now)) {
                valid = false;
                msgs.add("License not issued as of today");
            }
            
        } catch (Exception e) {
            valid = false;
            msgs.add("'issued_date' not valid");
        }
        
        try {
            Date exd = parseDate(expiryDate);
            
            if(exd.before(now)) {
                valid = false;
                msgs.add("License is expired");
            } else {
                isExpired = false;
                expiresInDays = TimeUnit.DAYS.convert(exd.getTime()-now.getTime(), TimeUnit.MILLISECONDS); 
            }
            
        } catch (Exception e) {
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
            valid = false;
            msgs.add("'start_date' not valid");
        }
        
        if(clusterName == null || clusterName.isEmpty()) {
            valid = false;
            msgs.add("'cluster_name' must not be empty or null");
        } /*else {
            if(!WildcardMatcher.match(clusterName.toLowerCase(), clusterService.getClusterName().value().toLowerCase())) {
                valid = false;
                msgs.add("Your cluster name '"+clusterService.getClusterName().value().toLowerCase()+"' does not match '"+clusterName+"'");
            }  
        }*/

        final int numberOfNodes = clusterService.state().getNodes().getSize();
        
        if(numberOfNodes > allowedNodeCount) {
            valid = false;
            msgs.add("Only "+allowedNodeCount+" node(s) allowed but you run "+numberOfNodes+" node(s)");
        }
        
        final String nodes = allowedNodeCount > 1500 ?"unlimited":String.valueOf(allowedNodeCount);

        if(!valid) {
            prodUsage = "No, because you have no valid license!";
            action = "Purchase a license. Visit https://floragunn.com/searchguard-validate-license or write to <sales@floragunn.com>";
        } else {
            prodUsage = "Yes, one cluster with all commercial features on "+nodes+" nodes";
            action = "";
        }
    }
    
    public enum Type {
        FULL,
        SME,
        SINGLE,
        ACADEMIC,
        OEM,
        TRIAL
    }
   
    private static Date parseDate(String date) throws ParseException {
        return new SimpleDateFormat("yyyy-MM-dd").parse(date);
    }
    
    private static String addDays(String date, long days) {
        try {
            return new SimpleDateFormat("yyyy-MM-dd").format(new Date(parseDate(date).getTime()+(days*1000L*60L*60L*24L)));
        } catch (Exception e) {
            return e.toString();
        } 
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

    @Override
    public String toString() {
        return "SearchGuardLicense [uid=" + uid + ", type=" + type + ", issueDate=" + issueDate + ", expiryDate=" + expiryDate
                + ", issuedTo=" + issuedTo + ", issuer=" + issuer + ", startDate=" + startDate + ", majorVersion=" + majorVersion
                + ", clusterName=" + clusterName + ", allowedNodeCount=" + allowedNodeCount + ", msgs=" + msgs + ", expiresInDays="
                + expiresInDays + ", isExpired=" + isExpired + ", valid=" + valid + ", action=" + action + ", prodUsage=" + prodUsage
                + ", clusterService=" + clusterService + ", getMsgs()=" + getMsgs() + ", getExpiresInDays()=" + getExpiresInDays()
                + ", isExpired()=" + isExpired() + ", isValid()=" + isValid() + ", getAction()=" + getAction() + ", getProdUsage()="
                + getProdUsage() + "]";
    }
}
