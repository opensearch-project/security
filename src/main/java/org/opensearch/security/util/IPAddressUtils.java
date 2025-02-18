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

package org.opensearch.security.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.support.SecurityUtils;

public class IPAddressUtils {

    protected final static Logger log = LogManager.getLogger(SecurityUtils.class);
    private static final String IP_ADDRESS = "(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})";
    private static final String SLASH_FORMAT = IP_ADDRESS + "/(\\d{1,2})"; // 0 -> 32
    private static final Pattern IPV4_CIDR_PATTERN = Pattern.compile(SLASH_FORMAT);

    /**
     * Creates a map of CIDR strings to their corresponding SubnetInfo objects
     *
     * @param hosts List of CIDR patterns to process
     * @return Map of valid CIDR strings to their SubnetInfo objects
     */
    public static Map<String, SubnetUtils.SubnetInfo> createSubnetUtils(List<String> hosts) {
        if (hosts == null || hosts.isEmpty()) {
            return Collections.emptyMap();
        }

        return hosts.stream()
            .filter(Objects::nonNull)
            .collect(
                Collectors.toMap(
                    cidr -> cidr,
                    IPAddressUtils::getSubnetForCidr,
                    (existing, replacement) -> existing,
                    () -> new HashMap<>(hosts.size())
                )
            );
    }

    /**
     * Creates a SubnetInfo object for a given CIDR pattern
     *
     * @param cidr CIDR pattern to process
     * @return SubnetInfo object for the given CIDR
     */
    private static SubnetUtils.SubnetInfo getSubnetForCidr(String cidr) {
        SubnetUtils utils = new SubnetUtils(cidr);
        utils.setInclusiveHostCount(true);
        return utils.getInfo();
    }

    /**
     * Validates if a given string matches IPv4 CIDR pattern
     *
     * @param cidr String to validate
     * @return true if the string is a valid IPv4 CIDR pattern, false otherwise
     */
    public static boolean isValidIpv4Cidr(String cidr) {
        return cidr != null && IPV4_CIDR_PATTERN.matcher(cidr).matches();
    }
}
