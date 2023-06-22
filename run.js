// @ts-check

import { readFileSync } from "node:fs";
import core from "@actions/core";

import { main } from "./main.js";
import { $ } from "execa";

const workspacePath = String(core.getInput("workspace-path"));
const eventPath = String(core.getInput("event-path"));

core.debug(`workspacePath: ${workspacePath}`);
core.debug(`event_path: ${eventPath}`);

/** @type {import("@octokit/webhooks-types").PullRequestEvent} */
const event = JSON.parse(readFileSync(eventPath, "utf8"));

core.debug(`event: ${JSON.stringify(event, null, 2)}`);

main(workspacePath, event, core, $);
