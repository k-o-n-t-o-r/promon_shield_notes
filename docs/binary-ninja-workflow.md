# Binary Ninja workflow

## 1. Build an analysis ELF

Start with an authorized original ELF and, when available, a flat first-load
runtime image:

```sh
python3 scripts/merge_runtime_image.py \
  original.so runtime.bin artifacts/runtime-expanded.so
```

This copies only file-backed `PT_LOAD` bytes. Program headers and load
addresses remain unchanged.

Recover function starts from the retained GNU EH-frame search table:

```sh
python3 scripts/elf_symbolize_eh_frame.py \
  artifacts/runtime-expanded.so artifacts/runtime-symbolized.so
```

The output is analysis-only. It adds section headers, a static string table,
and one `STT_FUNC` symbol for each FDE start.

## 2. Apply durable annotations in the GUI

Keep names, prototypes, types, and comments in a private JSON file instead of
making the `.bndb` the only source of truth. Install the small UI plugin by
symlinking it into Binary Ninja's user plugin directory:

```sh
ln -s /path/to/promon_shield/binaryninja/ui_plugin \
  ~/.binaryninja/plugins/promon-research
```

Restart Binary Ninja, open the analysis view, then use:

```text
Promon Research > Apply annotations JSON
Promon Research > Export annotations JSON
```

The apply command changes the open view; save the database normally after
reviewing the result. An example schema is available at
`binaryninja/annotations.example.json`.

For Binary Ninja licenses that permit headless API use, the same core also has
a CLI:

```sh
BN_LICENSE_FILE=/path/to/license.dat \
python3 binaryninja/annotations.py apply \
  artifacts/runtime-symbolized.so private/annotations.json \
  --output artifacts/runtime-symbolized.bndb

BN_LICENSE_FILE=/path/to/license.dat \
python3 binaryninja/annotations.py export \
  artifacts/runtime-symbolized.bndb private/annotations-export.json
```

Personal editions may restrict headless analysis; use the GUI plugin or the
official MCP interface in that case.

Review the export before treating it as the canonical file. Binary Ninja type
rendering can be lossy for complex named dependencies, so keep C type source
under the top-level `types` array manually.

## 3. Recover CFF cautiously

The research used MikuCffHelper at a pinned upstream commit with a small patch:

- Binary Ninja 6 commands for automatic deflattening and graph export;
- backward propagation through dispatcher-state aliases;
- one dispatcher rewrite per explicit action;
- a non-mutating JSON graph export including side-effect signatures.

The patch is at:

```text
binaryninja/mikucffhelper-bn6.patch
```

Apply it to a clean checkout:

```sh
git clone https://github.com/ltlly/MikuCffHelper.git
cd MikuCffHelper
git checkout 2c1e634
git apply /path/to/promon_shield/binaryninja/mikucffhelper-bn6.patch
```

Do not copy a third-party plugin snapshot into this repository. The patch keeps
the upstream history and license boundary explicit.

## 4. Side-effect verifier

For each candidate function:

1. export the graph;
2. count calls before mutation;
3. record call addresses and direct syscall sites;
4. record stores to globals and pointed-to memory;
5. record `mprotect`, cache-maintenance, lock, and cleanup operations;
6. run one dispatcher rewrite;
7. repeat the inventory;
8. reject any unexplained loss.

One nested rewrite in the observed sample removed a real call. A later
one-level rewrite preserved all callsites and was accepted. The difference was
not obvious from decompiler readability.

## 5. Address conventions

Private annotation files should state:

- whether addresses are ELF virtual addresses or Binary Ninja rebased
  addresses;
- the analysis image base;
- the build hash next to the private annotation file;
- whether a function came from static bytes, a runtime dump, or transient
  event-directed memory.

`annotations.py` applies an optional integer `slide` from the JSON. Keep the
stored addresses in one coordinate system and use the slide only at import.
