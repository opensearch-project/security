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

const fs = require('fs')
const yaml = require('yaml')

function checkPermissionsOrder(file, fix = false) {
  const contents = fs.readFileSync(file, 'utf8')
  const doc = yaml.parseDocument(contents, { keepCstNodes: true })
  const roles = doc.contents?.items || []
  let requiresChanges = false
  roles.forEach(role => {
    const itemsFromRole = role?.value?.items;

    const clusterPermissions = itemsFromRole?.filter(item => item.key && item.key.value === 'cluster_permissions');
    requiresChanges |= checkPermissionsOrdering(clusterPermissions);


    const indexPermissionsArray = itemsFromRole?.filter(item => item.key && item.key.value === 'index_permissions');
    const indexPermissionObj = indexPermissionsArray?.[0]?.value;
    const indexPermissionItems = indexPermissionObj?.items[0]?.items;
    const allowedIndexActions = indexPermissionItems?.filter(item => item.key && item.key.value === 'allowed_actions');
    
    requiresChanges |= checkPermissionsOrdering(allowedIndexActions);
  })

  if (fix && requiresChanges) {
    const newContents = doc.toString()
    fs.writeFileSync(file, newContents, 'utf8')
  }

  return requiresChanges
}

/*
  Checks the permissions ordering
  
  returns false if they are already stored
  returns true if the permissions were not sored, note the permissions object are sorted as a side effect of this function
*/
function checkPermissionsOrdering(permissions) {
  let requiresChanges = false;
  if (!permissions) {
    return requiresChanges;
  }
  permissions.forEach(permission => {
      const items = permission.value.items;
      const originalItems = JSON.stringify(items);
      items.sort();
      const sortedItems = JSON.stringify(items);

      // If the original items and sorted items are not the same, then changes are required
      if (originalItems !== sortedItems) {
        requiresChanges = true;
      }
  });
  return requiresChanges;
}

// Example usage
const args = process.argv.slice(2)
if (args.length === 0) {
  console.error('Usage: node check-permissions-order.js <file> [--fix] [--silent]')
  process.exit(1)
}
const filePath = args[0]
const fix = args.includes('--fix')
const silent = args.includes('--silent')
if (checkPermissionsOrder(filePath, fix)) {
  if (fix) {
    if (!silent) { console.log(`${filePath} has been updated.`) }
  } else {
    if (!silent) { console.error(`Error: ${filePath} requires changes.`) }
    process.exit(1)
  }
} else {
  if (!silent) { console.log(`${filePath} is up-to-date.`) }
}
