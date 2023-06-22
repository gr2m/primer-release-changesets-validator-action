// @ts-check

import { readFileSync } from "node:fs";
import core from "@actions/core";

import { main } from "./main.js";
import { $ } from "execa";

const workspacePath = String(core.getInput("workspace-path"));

/** @type {import("@octokit/webhooks-types").PullRequestEvent} */
const event = JSON.parse(readFileSync(core.getInput("event-path"), "utf8"));

main(workspacePath, event, core, $);
