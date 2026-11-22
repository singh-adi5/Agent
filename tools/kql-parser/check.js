#!/usr/bin/env node
// Parse and analyse KQL with Microsoft's Kusto language service.
//
// Reads a JSON array of {label, query} on stdin (python -m tools.catalog prints it)
// and fails on any syntax error or any reference to a column that is not in
// tools/securityevent.schema. It does not run the queries.
"use strict";
require("@kusto/language-service-next/bridge.min.js");
require("@kusto/language-service-next/Kusto.Language.Bridge.min.js");
const fs = require("fs");
const path = require("path");

const schemaFile = process.argv[2] || path.join(__dirname, "..", "securityevent.schema");
const columns = fs
  .readFileSync(schemaFile, "utf8")
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"));

const symbols = Kusto.Language.Symbols;
const table = new symbols.TableSymbol.$ctor7("SecurityEvent", `(${columns.join(", ")})`, null);
const database = new symbols.DatabaseSymbol.$ctor3("workspace", null, [table], false);
const globals = Kusto.Language.GlobalState.Default.WithDatabase(database);

const entries = JSON.parse(fs.readFileSync(0, "utf8"));
if (!Array.isArray(entries) || entries.length === 0) {
  console.error("FAIL no queries on stdin");
  process.exit(1);
}

let failures = 0;
for (const { label, query } of entries) {
  const diagnostics = Kusto.Language.KustoCode.ParseAndAnalyze(query, globals).GetDiagnostics();
  if (diagnostics.Count === 0) {
    console.log(`ok   ${label}`);
    continue;
  }
  failures += 1;
  console.log(`FAIL ${label}`);
  for (let i = 0; i < diagnostics.Count; i += 1) {
    const item = diagnostics.getItem(i);
    const line = query.slice(0, item.Start).split("\n").length;
    console.log(`     line ${line}: ${item.Message}`);
  }
}
console.log(`${entries.length - failures} of ${entries.length} queries parsed`);
process.exit(failures ? 1 : 0);
