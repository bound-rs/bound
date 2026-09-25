#!/usr/bin/env node
// md2html: renders Markdown (with optional YAML front matter) as a
// standalone HTML page, using the `marked` and `yaml` packages.

import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { marked } from "marked";
import { parse as parseYaml } from "yaml";

const USAGE = `usage: md2html [--template FILE] [--title TITLE] [-o FILE] [FILE]

Renders Markdown (FILE, or standard input) as an HTML page. YAML front
matter between --- lines sets page variables (title, author, ...). In the
template, {{name}} is replaced by the variable "name" (escaped) and
{{content}} by the rendered Markdown. The template is --template FILE,
else $MD2HTML_TEMPLATE, else the built-in templates/page.html.`;

/** Splits YAML front matter from the Markdown that follows it. */
export function frontMatter(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(text);
  if (!match) return { data: {}, body: text };
  const data = parseYaml(match[1]) ?? {};
  if (typeof data !== "object" || Array.isArray(data)) {
    throw new Error("front matter must be a YAML mapping");
  }
  return { data, body: text.slice(match[0].length) };
}

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Renders Markdown into `template`. */
export function render(markdown, template, overrides = {}) {
  const { data, body } = frontMatter(markdown);
  const vars = { ...data, ...overrides };
  vars.title ??= "Untitled";
  const content = marked.parse(body);
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, name) =>
    name === "content" ? content : escapeHtml(String(vars[name] ?? "")),
  );
}

function main(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      template: { type: "string" },
      title: { type: "string" },
      output: { type: "string", short: "o" },
      help: { type: "boolean", short: "h" },
    },
    allowPositionals: true,
  });
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  if (positionals.length > 1) {
    console.error(USAGE);
    return 2;
  }
  // The built-in template is found next to this script: templates/ sits
  // beside src/ (and beside build/, where the bundled script goes).
  const template = readFileSync(
    values.template ?? process.env.MD2HTML_TEMPLATE ?? new URL("../templates/page.html", import.meta.url),
    "utf8",
  );
  const markdown = readFileSync(positionals[0] ?? process.stdin.fd, "utf8");
  const overrides = values.title === undefined ? {} : { title: values.title };
  const html = render(markdown, template, overrides);
  if (values.output) {
    writeFileSync(values.output, html);
  } else {
    process.stdout.write(html);
  }
  return 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  console.error(`md2html: ${error.message}`);
  process.exitCode = 1;
}
