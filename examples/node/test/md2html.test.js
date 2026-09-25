import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const script = fileURLToPath(new URL("../src/md2html.js", import.meta.url));
const sample = fileURLToPath(new URL("../samples/post.md", import.meta.url));
const dark = fileURLToPath(new URL("../templates/dark.html", import.meta.url));

function md2html(args, options = {}) {
  const result = spawnSync(process.execPath, [script, ...args], { encoding: "utf8", ...options });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

test("front matter sets the page variables", () => {
  const html = md2html([sample]);
  assert.match(html, /<title>Release notes<\/title>/);
  assert.match(html, /<p class="byline">The build team<\/p>/);
  assert.match(html, /<strong>one executable<\/strong>/);
});

test("options override the front matter, and variables are escaped", () => {
  const html = md2html(["--title", "<Notes & more>", sample]);
  assert.match(html, /<title>&#60;Notes &#38; more&#62;<\/title>/);
});

test("the template can come from the environment, the Markdown from stdin", () => {
  const html = md2html([], { input: "# Hi\n", env: { ...process.env, MD2HTML_TEMPLATE: dark } });
  assert.match(html, /<body class="dark">/);
  assert.match(html, /<h1>Untitled<\/h1>/);
  assert.match(html, /<h1>Hi<\/h1>/);
});
