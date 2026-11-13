// SPDX-License-Identifier: BSD-3-Clause
import { build } from "esbuild";
import { parse } from "acorn";
import ts from "typescript";
import { analyze } from "eslint-scope";
import { fullAncestor } from "acorn-walk";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const banned = new Set(["eval", "Function", "AsyncFunction", "GeneratorFunction", "fetch",
  "XMLHttpRequest", "WebSocket", "WebTransport", "EventSource", "localStorage", "sessionStorage",
  "indexedDB", "caches", "cookie", "navigator", "window", "document", "globalThis", "self",
  "process", "require", "Deno", "Bun", "Worker", "SharedWorker", "importScripts",
  "getPrototypeOf", "getOwnPropertyDescriptor", "getOwnPropertyDescriptors", "defineProperty", "defineProperties", "setPrototypeOf", "preventExtensions", "seal", "assign", "__defineGetter__", "__defineSetter__",
  "constructor", "prototype", "__proto__", "Reflect", "Proxy", "global",
  "RTCPeerConnection", "RTCDataChannel", "WebSocketStream", "File", "FileReader",
  "FileSystemFileHandle", "FileSystemDirectoryHandle", "showOpenFilePicker", "showDirectoryPicker",
  "setTimeout", "setInterval", "Request", "Response", "Headers"]);
function lintSource(source) {
  const file = ts.createSourceFile("form.tsx", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  if (file.parseDiagnostics.length) throw Error("invalid TSX source");
  function visit(node) {
    if (ts.isModuleDeclaration(node) && (node.flags & ts.NodeFlags.GlobalAugmentation)) return; // erased JSX types
    if (ts.isIdentifier(node) && (node.text === "Object" || node.text === "JSON")) {
      const parent = node.parent;
      const allowed = node.text === "Object" ? ["freeze"] : ["parse", "stringify"];
      if (!ts.isPropertyAccessExpression(parent) || parent.expression !== node || !allowed.includes(parent.name.text)) throw Error("intrinsic alias or member forbidden");
    }
    if (ts.isIdentifier(node) && banned.has(node.text)) throw Error(`forbidden source identifier: ${node.text}`);
    if (ts.isImportDeclaration(node) || node.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isExportDeclaration(node) && node.moduleSpecifier)) throw Error("source module loading forbidden");
    if (ts.isElementAccessExpression(node)) {
      const property = node.argumentExpression;
      if (!ts.isStringLiteral(property) && !ts.isNumericLiteral(property)) throw Error("source computed access forbidden");
      if (ts.isStringLiteral(property) && banned.has(property.text)) throw Error("forbidden source property");
    }
    ts.forEachChild(node, visit);
  }
  visit(file);
}
export function lint(code) {
  const tree = parse(code, { ecmaVersion: "latest", sourceType: "module", ranges: true });
  const scopes = analyze(tree, { ecmaVersion: 2022, sourceType: "module" });
  const allowed = new Set(["Object", "JSON", "__rf_commit"]);
  for (const reference of scopes.globalScope.through) {
    if (!allowed.has(reference.identifier.name)) throw Error(`ambient API forbidden: ${reference.identifier.name}`);
  }
  fullAncestor(tree, (node, _state, ancestors) => {
    if (node.type === "Identifier" && (node.name === "Object" || node.name === "JSON")) {
      const parent = ancestors.at(-2);
      const allowed = node.name === "Object" ? ["freeze"] : ["parse", "stringify"];
      if (parent?.type !== "MemberExpression" || parent.object !== node || parent.computed || !allowed.includes(parent.property.name)) throw Error("intrinsic alias or member forbidden");
    }
    if (node.type === "ImportExpression" || node.type === "ImportDeclaration" || node.type === "ExportAllDeclaration" ||
        (node.type === "ExportNamedDeclaration" && node.source)) throw Error("module loading forbidden");
    if (node.type === "Identifier" && banned.has(node.name)) throw Error(`forbidden identifier: ${node.name}`);
    if (node.type === "MemberExpression") {
      if (node.computed && node.property.type !== "Literal") throw Error("computed access forbidden");
      if (node.property.type === "Literal" && banned.has(node.property.value)) throw Error("forbidden property");
    }
  });
}
function checkBundle(actual, expected) { assert.equal(actual, expected, "bundle drift: run npm run build"); }
if (process.argv.includes("--test")) {
  assert.throws(() => checkBundle("signed-bundle!", "signed-bundle"), undefined, "bundle drift must fail the CI check");
  for (const sample of ["eval('x')", "new Function('x')", "import('x')", "fetch('x')",
    "localStorage.getItem('x')", "Object['constructor']('x')", "const e = ev\\u0061l; e('x')",
    "const k='fetch'; x[k]('x')", "export {x} from 'x'", "RTCPeerConnection()", "Object.defineProperty(Object.getPrototypeOf([]),'map',{value(){}})",
    "const O=Object; O.freeze({})", "Object.assign({}, {})", "Object.setPrototypeOf([], null)", "JSON.constructor('x')"]) {
    assert.throws(() => lint(sample), undefined, `build lint accepted ${sample}`);
    assert.throws(() => lintSource(`if(false){${sample}}`), undefined, `source lint accepted dead code ${sample}`);
  }
  lintSource("export {}; declare global { namespace JSX { interface IntrinsicElements {} } }");
  assert.throws(() => lint("unrecognizedAmbientAPI()"), undefined, "unknown ambient APIs must fail closed");
  lint("export function render(input){__rf_commit(JSON.stringify(JSON.parse(input)))}");
  console.log("LINT_TESTS_OK");
} else {
  const base = new URL("./", import.meta.url);
  lintSource(await readFile(new URL("form.tsx", base), "utf8"));
  const result = await build({ entryPoints: [fileURLToPath(new URL("form.tsx", base))],
    bundle: true, format: "esm", platform: "neutral", target: "es2020", jsxFactory: "h",
    legalComments: "none", write: false, metafile: true });
  if (Object.keys(result.metafile.inputs).length !== 1) throw Error("only the project component source is allowed");
  const code = "// SPDX-License-Identifier: BSD-3-Clause\n" + result.outputFiles[0].text;
  lint(code);
  const destination = new URL("form.js", base);
  if (process.argv.includes("--check")) {
    checkBundle(await readFile(destination, "utf8"), code);
    console.log("BUNDLE_CHECK_OK");
  } else { await writeFile(destination, code); console.log("BUNDLE_OK"); }
}
