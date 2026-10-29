# Markdown with program examples

Real README files whose fenced code examples (npx commands, proxy setup, a
hex-formatting snippet) can make a content scorer call them JavaScript. Used
by `original_readmes_with_program_examples_remain_markdown` in
`src/fileid/markdown.rs`, which asserts that each identifies as `markdown`
with no extension mismatch. Unmodified.

| Fixture | Upstream package | License | SHA-256 |
|---|---|---|---|
| `debug-readme.md` | `debug` | MIT | `486cb669048bd5014adf9ea117e27a45c4e61b0e668f464c724273beb8170797` |
| `https-proxy-agent-readme.md` | `https-proxy-agent` | MIT | `462697a398c1bbbfd771bf58829aba65a1c620b072749a76a6ab1c25f62e9edc` |
| `proxy-agent-readme.md` | `proxy-agent` | MIT | `02f4d7c654ebdedbff38d63a65b116cc48b13b49573cf83784b91dbf92a579d3` |
| `puppeteer-browsers-readme.md` | `@puppeteer/browsers` | Apache-2.0 | `08ceb841b14b185ad478b0338980f1ac06124b296e0931d8d73cbb088c5e55fa` |
| `appsec-front-matter-policy.md` | (see below) | (see below) | `e7d789530d7de55a029caad53b451c0b17fa70bacc7cd3aca273f5f4e310a7a1` |

The four npm READMEs are the `node_modules/<package>/README.md` members of the
`naatin777.latex-graphics-helper` 0.4.0 VS Code extension (archive SHA-256
`ca4dd0641078ef575ce3b88d6d16f75ddbe2f64e6ef14e58c56294eb47acd7d3`);
`provenance.json` maps each fixture to its archive member path.

`appsec-front-matter-policy.md` is an instruction file aimed at AI coding
assistants, with YAML front matter before the first heading. It is kept for
that front matter, which must not stop the document from being Markdown.
