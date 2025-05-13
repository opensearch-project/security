<img src="https://opensearch.org/assets/img/opensearch-logo-themed.svg" height="64px">

## Contributing to this Project

OpenSearch is a community project that is built and maintained by people just like **you**.
[This document](https://github.com/opensearch-project/.github/blob/main/CONTRIBUTING.md) explains how you can contribute to this and related projects.

Visit the following link(s) for more information on specific practices:

- [Triaging](./TRIAGING.md)
- [Changelog](#changelog)

## How we work

#### Quality and security form the foundation of our efforts
* We deliver quality security solutions by understanding issues thoroughly, acting iteratively, and validating solutions through rigorous testing.
* We hold security to the highest standards of quality. Quality is the first step in building trust with users, stakeholders, and our community as a whole.
* We move swiftly to solve problems. But we don’t sacrifice quality to achieve quick wins, meet performance indicators, or get the bragging rights related to launching popular, high-profile features.



#### Privacy won’t be compromised
* Privacy is a key part of security, and we make sure it isn’t compromised in the pursuit of creating benefits.
* When we make decisions, we carefully consider any potential impacts to privacy and make sure those decisions protect our users’ and stakeholders’ data.
* We maintain a focus on creating software that empowers cluster administrators to keep their sensitive data safe.



#### Transparent collaboration creates secure outcomes
* Transparent collaboration promotes community inclusion, creates a space for concise and authentic communication, and supports accountability.
* We operate through transparent collaboration. We believe a secure product is built through diverse perspectives, knowledge sharing, candid discussions, and doing our work in the open when and where it’s safe to do so.
* We are relationship builders who create safe, respectful, and accessible spaces for everyone so we can engage and work towards the common goal of building secure solutions.
* When circumstances do require privacy, we make every effort to quickly resolve those requirements and return circumstances to a state of full visibility with our community and collaborators.

## Changelog

OpenSearch maintains version specific changelog by enforcing a change to the ongoing [CHANGELOG](CHANGELOG.md) file adhering to the [Keep A Changelog](https://keepachangelog.com/en/1.0.0/) format. The purpose of the changelog is for the contributors and maintainers to incrementally build the release notes throughout the development process to avoid a painful and error-prone process of attempting to compile the release notes at release time. On each release the "unreleased" entries of the changelog are moved to the appropriate release notes document in the `./release-notes` folder. Also, incrementally building the changelog provides a concise, human-readable list of significant features that have been added to the unreleased version under development.

### Which changes require a CHANGELOG entry?
Changelogs are intended for operators/administrators, developers integrating with libraries and APIs, and end-users interacting with OpenSearch Dashboards and/or the REST API (collectively referred to as "user"). In short, any change that a user of OpenSearch might want to be aware of should be included in the changelog. The changelog is _not_ intended to replace the git commit log that developers of OpenSearch itself rely upon. The following are some examples of changes that should be in the changelog:

- A newly added feature
- A fix for a user-facing bug
- Dependency updates
- Fixes for security issues

The following are some examples where a changelog entry is not necessary:

- Adding, modifying, or fixing tests
- An incremental PR for a larger feature (such features should include _one_ changelog entry for the feature)
- Documentation changes or code refactoring
- Build-related changes

Any PR that does not include a changelog entry will result in a failure of the validation workflow in GitHub. If the contributor and maintainers agree that no changelog entry is required, then the `skip-changelog` label can be applied to the PR which will result in the workflow passing.

### How to add my changes to [CHANGELOG](CHANGELOG.md)?

Adding in the change is two step process:
1. Add your changes to the corresponding section within the CHANGELOG file with dummy pull request information, publish the PR
2. Update the entry for your change in [`CHANGELOG.md`](CHANGELOG.md) and make sure that you reference the pull request there.
