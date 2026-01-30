# wormhole-svm-test

Testing utilities for Solana programs integrating with Wormhole.

## Features

- **Guardian signing**: Create test guardians with configurable keys, sign VAA bodies
- **VAA construction**: Build and sign VAAs for testing
- **LiteSVM integration** (optional): Load Wormhole programs and set up guardian accounts

## Usage

```rust
use wormhole_svm_test::{TestGuardian, TestGuardianSet, TestVaa};

// Create guardians
let guardians = TestGuardianSet::single(TestGuardian::default());

// Build and sign a VAA
let vaa = TestVaa::new(
    1,                    // emitter chain (Solana)
    [0xAB; 32],           // emitter address
    42,                   // sequence
    vec![1, 2, 3, 4],     // payload
);
let signed_vaa = vaa.sign(&guardians);
let signatures = vaa.guardian_signatures(&guardians);
```

### With LiteSVM

Enable the `litesvm` feature:

```toml
[dev-dependencies]
wormhole-svm-test = { version = "0.1", features = ["litesvm"] }
```

```rust
use wormhole_svm_test::{
    TestGuardianSet, TestGuardian,
    setup_wormhole, WormholeProgramsConfig,
};
use litesvm::LiteSVM;

let mut svm = LiteSVM::new();
let guardians = TestGuardianSet::single(TestGuardian::default());

let wormhole = setup_wormhole(
    &mut svm,
    &guardians,
    0, // guardian set index
    WormholeProgramsConfig::default(),
)?;

// wormhole.guardian_set is the PDA address
```

## Obtaining Wormhole Program Binaries

The LiteSVM helpers require Wormhole program binaries. Dump them from mainnet:

```bash
solana account -u mainnet \
    HDwcJBJXjL9FpJ7UBsYBtaDjsBUhuLCUYoz3zr8SWWaQ \
    --output-file fixtures/verify_vaa_shim.so \
    --output json-compact

solana account -u mainnet \
    worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth \
    --output-file fixtures/core_bridge.so \
    --output json-compact
```

Or set `WORMHOLE_FIXTURES_DIR` to point to existing binaries.

## Multi-Guardian Testing

```rust
// Generate deterministic guardians
let guardians = TestGuardianSet::generate(13, 12345);

// Sign with all
let signed = vaa.sign(&guardians);

// Sign with quorum subset
let signed = vaa.sign_with(&guardians, &[0, 1, 2, 3, 4, 5, 6, 7, 8]);
```

## License

Apache-2.0
