# Private recovery profiles

`recover_main_region.py` requires an exact-build JSON profile. Real profiles
are ignored by git because they contain build-specific hashes, offsets,
lengths, and nonce material.

Copy `example.json` to a different name and fill it locally. The example uses
placeholder values and cannot recover a real binary.

The script deliberately validates:

- the encrypted ELF SHA-256;
- the recovered plaintext SHA-256;
- all virtual-address-to-file mappings;
- the optional runtime image byte for byte.

Do not weaken those checks to make a nearby app update "work."
