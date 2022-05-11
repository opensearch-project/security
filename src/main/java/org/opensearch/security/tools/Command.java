/*
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.tools;

public abstract class Command {
    public abstract int execute(final String[] args) throws Exception;

    public abstract String describe();

    public abstract void usage();

    public void exit(int status) {
        System.exit(status);
    }

    public void main(final String[] args) throws Exception {
        try{
            final int returnCode = execute(args);
            exit(returnCode);
        } catch (Throwable e) {
            System.out.println(String.format("Unexpected error: %s. See stack trace below\n %s",
                    e.getMessage(), e.getStackTrace()));
            exit(-1);
        }
    }
}
