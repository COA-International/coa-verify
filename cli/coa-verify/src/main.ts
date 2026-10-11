#!/usr/bin/env node
import { run } from "./cli.js";

run(process.argv.slice(2), {
  stdout: (s) => void process.stdout.write(s),
  stderr: (s) => void process.stderr.write(s),
  env: process.env,
  cwd: process.cwd(),
}).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`internal error: ${(err as Error).message}\n`);
    process.exitCode = 70;
  },
);
