# primer-release-changesets-validator-action

> Validates `changesets/*.md` files in `primer/*` pull requests

## Usage

```yaml
name: Changesets
"on":
  pull_request:
    types: [opened, synchronize, reopened, labeled, unlabeled]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      - uses: gr2m/primer-release-changesets-validator-action@v1
```

## License

[MIT](LICENSE)
