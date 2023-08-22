#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.


# Search for System.out.println statements in Java code

# List of files or directories to exclude from the check
EXCLUDES=("./src/main/java/org/opensearch/security/tools"
 "./src/main/java/com/amazon/dlic/auth/http/kerberos/HTTPSpnegoAuthenticator.java")

# Function to check if a file or directory should be excluded
should_exclude() {
  local target="$1"
  for exclude in "${EXCLUDES[@]}"; do
    if [[ "$target" == "$exclude" || "$target" == "$exclude/"* ]]; then
      return 0 # Exclude
    fi
  done
  return 1 # Don't exclude
}

# Flag to indicate if any violations were found
found_violations=false

# Search for System.out.println statements in Java code, excluding specified files and directories
find . -type f -name '*.java' | while read -r file; do
  if should_exclude "$file"; then
    continue # Skip this file
  fi

  if grep -q 'System\.out\.println' "$file"; then
    echo "Error: Found System.out.println statements in $file."
    # shellcheck disable=SC2030
    found_violations=true
  fi
done

# shellcheck disable=SC2031
if [ "$found_violations" = true ]; then
  exit 1
fi

