#!/usr/bin/env node

import { runBootstrapMain } from "../lib/bootstrap.js";

await runBootstrapMain(process.argv.slice(2));
