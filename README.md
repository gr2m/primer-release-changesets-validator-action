# primer-release-changesets-validator-action

> Validates `changesets/*.md` files in `primer/*` pull requests

## Usage

```yaml
name: Primer Release
"on": pull_request

jobs:
  validate-changesets:
    name: Validate Changesets
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: gr2m/primer-release-changesets-validator-action@v1
```

## License

[MIT](LICENSE)
