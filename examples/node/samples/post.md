---
title: Release notes
author: The build team
---

# What changed

The build now produces **one executable** per tool:

- no `node_modules` to install on servers,
- no version drift between machines,
- the same command line everywhere.

```sh
./md2html notes.md > notes.html
```

Questions? See the [bound README](https://example.invalid/bound) & ask <us>.
