import { test, mock } from "node:test";
import { strict as assert } from "node:assert";

import { main } from "./main.js";

test("empty body", (t) => {
  const body = "";
  const setOutput = mock.fn();

  main(
    {
      setOutput,
    },
    { release: { body } }
  );

  assert.equal(setOutput.mock.calls.length, 0);
});

test("with some components", () => {
  const body = `### Patch Changes

### [Permalink to documentation](https://primer-b7eac8252f-13348165.drafts.github.io/)

-   First change

    <!-- Changed components: One, Two, Three -->

-   Second change

    <!-- Changed components: One, Three -->

-   Third change

    <!-- Changed components: _none_ -->

-   Fourth change

    more info

    <!-- Changed components: One, Two -->
`;

  const setOutput = mock.fn();
  main(
    {
      setOutput,
    },
    { release: { body } }
  );

  assert.equal(setOutput.mock.calls.length, 3);
  assert.deepEqual(setOutput.mock.calls[0].arguments, [
    "hasComponentChanges",
    "true",
  ]);
  assert.deepEqual(setOutput.mock.calls[1].arguments, [
    "changelogsByComponent",
    JSON.stringify({
      One: ["First change", "Second change", "Fourth change\nmore info"],
      Two: ["First change", "Fourth change\nmore info"],
      Three: ["First change", "Second change"],
    }),
  ]);
  console.log(setOutput.mock.calls[2].arguments[1]);
  assert.deepEqual(setOutput.mock.calls[2].arguments, [
    "changelogsByComponentMarkdown",
    `### One

- First change
- Second change
- Fourth change
more info

### Two

- First change
- Fourth change
more info

### Three

- First change
- Second change`,
  ]);
});
