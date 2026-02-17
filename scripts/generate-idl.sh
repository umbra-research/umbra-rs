#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "Generating Anchor IDL..."
# Build the program using Anchor to generate IDL
# Ensure 'idl-build' feature is active if needed, recent anchor versions might handle it defaults.
# But for verify build we used --lib.
# anchor build automatically uses [workspace] from Anchor.toml
RUSTFLAGS="--cfg procmacro2_semver_exempt" anchor build

echo "IDL generated at target/idl/umbra_program.json"
echo "Types generated at target/types/umbra_program.ts"

# Optional: If you have a frontend package, copy the IDL there.
# cp target/idl/umbra_program.json crates/umbra-interface/src/idl/
