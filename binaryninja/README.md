# Binary Ninja tooling

## Annotation commands

`annotations.py` is the format implementation and optional headless CLI.
`ui_plugin/` registers equivalent commands inside Binary Ninja, which is the
recommended route for Personal editions.

Install the UI plugin:

```sh
ln -s /path/to/promon_shield/binaryninja/ui_plugin \
  ~/.binaryninja/plugins/promon-research
```

Restart Binary Ninja and use the `Promon Research` command group. Real
annotation JSON belongs under the repository's ignored `private/` directory.

## MikuCffHelper patch

`mikucffhelper-bn6.patch` targets upstream commit `2c1e634` of
<https://github.com/ltlly/MikuCffHelper>. The upstream plugin identifies itself
as MIT-licensed in `plugin.json`; no upstream source or sample binary is
vendored here.

The patch adds the compatibility and safety changes described in
`../docs/binary-ninja-workflow.md`.
