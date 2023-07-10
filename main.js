// @ts-check

import { readFile } from "node:fs/promises";
import { join } from "node:path";

const REGEX_CHANGED_COMPONENTS = /<\!--\s*Changed components:(.*)\s*-->\s*$/;
const SUPPORTED_PRIMER_PACKAGES = ["@primer/react", "@primer/view-components"];
const SKIP_CHANGESETS_LABELS = ["skip changeset", "skip changelog"];
const SPECIAL_PACKAGE_NONE = "_none_";

/**
 * @param {string} workspacePath
 * @param {import("@octokit/webhooks-types").PullRequestEvent} event
 * @param {import("@actions/core")} core
 * @param {import("execa")["$"]} $
 */
export async function main(workspacePath, event, core, $) {
  const skipChangesetsLabel = event.pull_request.labels.find((label) =>
    SKIP_CHANGESETS_LABELS.includes(label.name)
  );

  // if pull request is a release pull request, skip changesets check
  if (event.pull_request.head.ref.startsWith("changeset-release/")) {
    core.info(`Changesets were skipped because this is a release pull request`);
    return;
  }

  // if skip changesets label is present, skip changesets check
  if (skipChangesetsLabel) {
    core.info(
      `Changesets were skipped because of the '${skipChangesetsLabel.name}' label`
    );
    return;
  }

  const packagePath = join(workspacePath, "package.json");
  let packageContents;
  try {
    packageContents = await readFile(packagePath, "utf8");
  } catch {
    core.setFailed(
      `Could not find package.json at ${packagePath}. Did you run actions/checkout?`
    );
    return;
  }

  /** @type {{name: string}} */
  const pkg = JSON.parse(packageContents);

  if (!SUPPORTED_PRIMER_PACKAGES.includes(pkg.name)) {
    core.setFailed(
      `This CI is only supported in the following packages: ${SUPPORTED_PRIMER_PACKAGES.join(
        ", "
      )}. Current package is ${pkg.name}`
    );
    return;
  }

  const primerPackages = getPrimerPackages(core, pkg.name, workspacePath);

  // fetch

  // get list of files changed in pull request
  let gitResult;

  try {
    gitResult =
      await $`git diff --name-only origin/${event.pull_request.base.ref}`;
  } catch {
    core.setFailed(
      `Could not find origin/${event.pull_request.base.ref}. Did you run actions/checkout with fetch-depth: 0?`
    );
    return;
  }

  const changedFilesLines = gitResult.stdout;

  // find paths to changeset files
  const changedChangesetFiles = changedFilesLines
    .split("\n")
    .filter((line) => line.startsWith(".changeset/"));

  if (changedChangesetFiles.length === 0) {
    core.setFailed(
      `No changeset found. If these changes should not result in a new version, apply the "skip changeset" label to this pull request. If these changes should result in a version bump, please add a changeset https://git.io/J6QvQ`
    );
    return;
  }

  const errors = [];
  for (const line of changedChangesetFiles) {
    try {
      const content = await readFile(line, "utf8");

      if (!REGEX_CHANGED_COMPONENTS.test(content)) {
        errors.push(`Could not find changed components in ${line}`);
        continue;
      }

      // @ts-expect-error - can't be null, we check above
      const changedComponentsString = content
        .match(REGEX_CHANGED_COMPONENTS)[1]
        .trim();

      if (changedComponentsString === SPECIAL_PACKAGE_NONE) {
        continue;
      }

      const changedComponents = changedComponentsString
        .split(",")
        .map((s) => s.trim());

      for (const changedComponent of changedComponents) {
        if (!primerPackages.includes(changedComponent)) {
          errors.push(`Unknown component "${changedComponent}".`);
        }
      }
    } catch (error) {
      if (error.code === "ENOENT") {
        core.info(`${line} has been deleted`);
        continue;
      }

      core.warning(`Could not read ${line}: ${error.message}`);
    }
  }

  if (errors.length > 0) {
    core.setFailed(
      errors.join("\n") +
        `

Known ${pkg.name} components: ${primerPackages.join(", ")}

Example:

---
"${pkg.name}": patch
---

Fixed this and that

<!-- Changed components: ${primerPackages[0]} -→
`
    );

    return;
  }

  core.info("All changesets are valid");
}

/**
 * @param {import("@actions/core")} core
 * @param {string} pkgName
 * @param {string} workspacePath
 *
 * @returns {string[]}
 */
function getPrimerPackages(core, pkgName, workspacePath) {
  if (pkgName === "@primer/react") {
    const componentsPath = join(workspacePath, "generated/components.json");
    core.info(
      `Loading components information for ${pkgName} from ${componentsPath}`
    );
    const { components } = require(componentsPath);
    return Object.values(components).map((component) => component.name);
  }

  if (pkgName === "@primer/view-components") {
    const componentsPath = join(workspacePath, "static/info_arch.json");

    core.info(
      `Loading components information for ${pkgName} from ${componentsPath}`
    );

    const components = require(componentsPath);
    return Object.values(components).map(
      (component) => component.fully_qualified_name
    );
  }

  core.setFailed(`Unknown package name: ${pkgName}`);
  process.exit(1);
}
