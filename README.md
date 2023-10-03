# `bwenv-setup` GitHub Action

This action sets up `bwenv` by downloading and caching a version of the `bwenv` binary and adding it to the PATH.

## Usage

### Inputs

- `version`: (Optional) The version of `bwenv` to use. Defaults to the latest release.

### Example Workflow

Here's a basic example to set up and use `bwenv` in your workflow:

```yaml
name: My Workflow

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v2

    - name: Setup bwenv
      uses: titanom/bwenv-setup@v1 # replace `v1` with your action's version
      with:
        version: 'latest' # or specify a version

    - name: Use bwenv
      run: |
        bwenv --version
