# Scripts

## Offline analysis

```text
merge_runtime_image.py      overlay available runtime PT_LOAD bytes
elf_symbolize_eh_frame.py   recover FDE starts as ELF function symbols
recover_main_region.py      reproduce the observed checksum/ChaCha8 unpacker
```

`recover_main_region.py` refuses an input whose SHA-256 does not match the
private profile. `merge_runtime_image.py` is analysis-only and reports how many
load segments were copied or skipped.

## Typical sequence

```sh
python3 scripts/recover_main_region.py \
  original.so profiles/local.json artifacts/recovered.so \
  --runtime runtime.bin \
  --metadata artifacts/recovered.json

python3 scripts/merge_runtime_image.py \
  original.so runtime.bin artifacts/runtime-expanded.so

python3 scripts/elf_symbolize_eh_frame.py \
  artifacts/runtime-expanded.so artifacts/runtime-symbolized.so
```

Keep the original ELF, private profile, runtime image, and generated analysis
artifacts under ignored storage.
