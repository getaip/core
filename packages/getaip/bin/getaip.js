#!/usr/bin/env node

import { runBootstrapMain } from "@getaip/cli";

await runBootstrapMain(process.argv.slice(2));
