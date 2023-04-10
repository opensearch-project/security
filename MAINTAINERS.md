- [Overview](#overview)
- [Current Maintainers](#current-maintainers)
- [Practices](#practices)
  - [Updating Practices](#updating-practices)
  - [Reverting Commits](#reverting-commits)
  - [Performing Revert](#performing-revert)
  - [Squashing a Pull Request](#squashing-a-pull-request)

## Overview

This document contains a list of maintainers in this repo. See [opensearch-project/.github/RESPONSIBILITIES.md](https://github.com/opensearch-project/.github/blob/main/RESPONSIBILITIES.md#maintainer-responsibilities) that explains what the role of maintainer means, what maintainers do in this and other repos, and how they should be doing it. If you're interested in contributing, and becoming a maintainer, see [CONTRIBUTING](CONTRIBUTING.md).

## Current Maintainers

| Maintainer       | GitHub ID                                             | Affiliation |
| ---------------- | ----------------------------------------------------- | ----------- |
| Chang Liu        | [cliu123](https://github.com/cliu123)                 | Amazon      |
| Darshit Chanpura | [DarshitChanpura](https://github.com/DarshitChanpura) | Amazon      |
| Dave Lago        | [davidlago](https://github.com/davidlago)             | Amazon      |
| Peter Nied       | [peternied](https://github.com/peternied)             | Amazon      |
| Craig Perkins    | [cwperks](https://github.com/cwperks)                 | Amazon      |
| Ryan Liang       | [RyanL1997](https://github.com/RyanL1997)             | Amazon      |
| Stephen Crawford | [scrawfor99](https://github.com/scrawfor99)           | Amazon      |
| Andriy Redko     | [reta](https://github.com/reta)                       | Aiven       |

## Practices

### Updating Practices

To ensure common practices as maintainers, all practices are expected to be documented here or enforced through github actions. There should be no expectations beyond what is documented in the repo [CONTRIBUTING.md](./CONTRIBUTING.md) and OpenSearch-Project [CONTRIBUTING.md](https://github.com/opensearch-project/.github/blob/main/CONTRIBUTING.md). To modify an existing processes or create a new one, make a pull request on this MAINTAINERS.md for review and merge it after all maintainers approve of it.

### Reverting Commits

There will be changes that destabilize or block contributions.  The impact of these changes will be localized on the repository or even the entire OpenSearch project.  We should bias towards keeping contributions unblocked by immediately reverting impacting changes, these reverts will be done by a maintainer.  After the change has been reverted, an issue will be openned to re-merge the change and callout the elements of the contribution that need extra examination such as additional tests or even pull request workflows.

Exceptional, instead of immediately reverting, if a contributor knows how and will resolve the issue in an hour or less we should fix-forward to reduce overhead.

### Performing Revert

Go to the pull request of the change that was an issue, there is a `Revert` button at the bottom.  If there are no conflicts to resolve, this can be done immediately bypassing standard approval.

Reverts can also be done via the command line using `git revert <commit-id>` and creating a new pull request.  If done in this way they should have references to the pull request that was reverted.

### Squashing a Pull Request

When a PR is going to be merged, our repositories are set to automatically squash the commits into a single commit.  This process needs human intervention to produce high quality commit messages, with the following steps to be followed as much as possible:

- The commit subject is clean and conveys what is being merged
- The commit body should include the details (if any) about the commit, typically inline with the PR description
- The commit body should include the 'Signed-Off-By:*' for all committers involved in the change.
- There need to be a matching 'Signed-Off-By:' line for the `This commit will be authored by *` email address otherwise backport DCO checks will fail.
