// @ts-check

const { readFile } = require("node:fs/promises");
const { join } = require("node:path");

const REGEX_CHANGED_COMPONENTS = /<\!--\s*Changed components:(.*)\s*-->\s*$/;

const SUPPORTED_PRIMER_PACKAGES = ["@primer/react", "@primer/view-components"];

/**
 * @param {string} workspacePath
 * @param {import("@octokit/webhooks-types").PullRequestEvent} event
 * @param {import("@actions/core")} core
 * @param {import("execa")["$"]} $
 */
export async function main(workspacePath, event, core, $) {
  const hasSkipChangesetsLabel = event.pull_request.labels.some(
    (label) => label.name === "skip changeset"
  );

  if (hasSkipChangesetsLabel) {
    core.info("Changesets were skipped because of the 'skip changeset' label");
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

  if (SUPPORTED_PRIMER_PACKAGES.includes(pkg.name)) {
    core.setFailed(
      `This CI is only supported in the following packages: ${SUPPORTED_PRIMER_PACKAGES.join(
        ", "
      )}. Current package is ${pkg.name}`
    );
    return;
  }

  const primerPackages = getPrimerPackages(core, pkg.name, workspacePath);

  // get list of files changed in pull request
  const { stdout: changedFilesLines } =
    await $`git diff --name-only ${event.repository.default_branch}`;

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
    const content = await readFile(line, "utf8");

    if (!REGEX_CHANGED_COMPONENTS.test(content)) {
      errors.push(`Could not find changed components in ${line}`);
      continue;
    }

    // @ts-expect-error - can't be null, we check above
    const changedComponents = content
      .match(REGEX_CHANGED_COMPONENTS)[1]
      .split(",")
      .map((s) => s.trim());

    for (const changedComponent of changedComponents) {
      if (!primerPackages.includes(changedComponent)) {
        errors.push(`Unknown component "${changedComponent}".`);
      }
    }
  }

  if (errors.length > 0) {
    core.setFailed(
      errors.join("\n") +
        "\n" +
        `Known ${pkg.name} components: ${primerPackages.join(", ")}`
    );
  }
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
