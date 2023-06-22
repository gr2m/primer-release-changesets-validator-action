// @ts-check

import { readFileSync } from "node:fs";
import core from "@actions/core";

import { main } from "./main.js";
import { $ } from "execa";

const workspacePath = String(process.env.GITHUB_WORKSPACE);

/** @type {import("@octokit/webhooks-types").PullRequestEvent} */
const event = JSON.parse(
  readFileSync(String(process.env.GITHUB_EVENT), "utf8")
);

main(workspacePath, event, core, $);
