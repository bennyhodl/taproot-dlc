# Taproot DLC Research Implementation

A research implementation of Discreet Log Contracts (DLCs) using Bitcoin's Taproot upgrade, demonstrating how modern Bitcoin script capabilities can enhance DLC construction and efficiency.

## Overview

This project explores the implementation of DLCs using Taproot's script-path spending and Schnorr signatures, providing improved privacy, efficiency, and flexibility compared to traditional DLC implementations. Instead of using complex multisig constructions in legacy script formats, this implementation leverages Taproot's native capabilities for cleaner, more private contract execution.

## What are Taproot DLCs?

### Traditional DLCs vs Taproot DLCs

**Traditional DLCs** typically use:

- P2WSH (Pay-to-Witness-Script-Hash) outputs for funding
- Complex multisig scripts exposed on-chain
- ECDSA adaptor signatures
- Multiple script branches visible during execution

**Taproot DLCs** leverage:

- P2TR (Pay-to-Taproot) outputs for funding
- Script-path spending with Taproot's privacy benefits (current implementation)
- Schnorr adaptor signatures
- Single script execution path, hiding unused contract branches
- **Future with Covenants**: CTV templates in merkle tree leaves for non-interactive setup

### Key Technical Improvements

1. **Enhanced Privacy**: Taproot outputs look identical to single-key spends until execution, providing better privacy for DLC participants.

2. **Improved Efficiency**: Schnorr signatures are more compact and allow for signature aggregation possibilities.

3. **Cleaner Script Construction**: Taproot's script-path spending allows for more intuitive script construction using `OP_CHECKSIGADD` for threshold signatures.

4. **Non-Interactive Setup (with Covenants)**: When combined with CTV + CSFS, DLCs can be set up non-interactively by encoding all spending conditions in the funding transaction's merkle tree.

5. **Scalable Outcome Handling**: Instead of creating separate CETs for each outcome, all possibilities are pre-committed in a single tree structure.

6. **Future Extensibility**: Foundation for advanced features like cross-input signature aggregation and more complex contract structures.

### CTV + CSFS

**Important**: Taproot DLCs on their own do not provide immediate substantial benefits beyond some privacy improvements with MuSig key-path spending. The transformative advantage comes when Taproot is combined with **covenants**, specifically CTV (CheckTemplateVerify) + CSFS (CheckSigFromStack).

With covenants, the architecture fundamentally changes:

- **Current Approach**: Create 1..n Contract Execution Transactions (CETs) requiring extensive interactive protocols
- **Covenant Approach**: Encode all spending paths as CTV templates within a single Taproot merkle tree
- **Result**: Parties only need to generate the same funding address - no back-and-forth exchange of adaptor signatures

This covenant-based approach leverages Taproot's merkle tree structure to its full potential, enabling **non-interactive DLC setup** where all possible contract outcomes are pre-committed in the funding transaction's script tree.

## Technical Architecture

### Core Components

#### DlcParty

The main participant in a DLC, containing:

- Schnorr keypair for funding transactions
- Schnorr context for adaptor signature operations
- Taproot wallet for UTXO management
- Blockchain interface for transaction operations

#### Contract Flow

1. **Offer Creation**: Offerer specifies contract terms, collateral, and oracle information
2. **Acceptance**: Acceptor agrees to terms and provides adaptor signatures for all Contract Execution Transactions (CETs)
3. **Signing**: Offerer verifies acceptor's signatures and provides their own adaptor signatures
4. **Broadcasting**: Final funding transaction is created and broadcasted

### Funding Script Construction (Script Path)

The current implementation uses Taproot's script-path spending for DLC execution. The funding script uses a Taproot output with a script-path containing a 2-of-2 threshold signature check:

```
<pubkey1> OP_CHECKSIG <pubkey2> OP_CHECKSIGADD 2 OP_NUMEQUALVERIFY
```

This script is committed to a Taproot output using:

- An internal key derived from both participants' public keys
- A single script leaf in the Merkle tree
- Standard Taproot commitment construction

**Note**: While this approach provides significant privacy improvements over legacy DLCs, it still requires revealing the script on-chain during execution. The ultimate privacy goal would be key-path spending with MuSig adaptor signatures (see roadmap).

### Adaptor Signature Protocol

1. **CET Construction**: For each possible oracle outcome, a Contract Execution Transaction is built
2. **Adaptor Signature Creation**: Each party creates adaptor signatures encrypted with the oracle's nonce for that outcome
3. **Verification**: Adaptor signatures are verified using the oracle's public nonce
4. **Settlement**: When the oracle publishes an attestation, the corresponding adaptor signature can be decrypted to complete the CET

### Oracle Integration

The implementation uses [Kormir](https://github.com/BitcoinDevShop/kormir) oracle announcements, supporting:

- Enumeration-based contracts (multiple discrete outcomes)
- Oracle nonce-based adaptor signature encryption
- Deterministic outcome-to-signature mapping

## Implementation Status

### ✅ Completed Features

- [x] Taproot funding script generation
- [x] Schnorr adaptor signature creation and verification
- [x] Full DLC protocol flow (Offer → Accept → Sign → Broadcast)
- [x] Integration with Taproot wallets
- [x] Enumeration contract support
- [x] Oracle announcement integration
- [x] Transaction fee calculation and UTXO management
- [x] Comprehensive test coverage

### 🚧 In Progress

- [ ] CET execution and spending
- [ ] Refund transaction implementation
- [ ] Enhanced error handling and recovery

### 📋 Roadmap

#### High Priority - Covenant Integration

- [ ] **CTV + CSFS Implementation**: Implement covenant-based DLCs using CheckTemplateVerify and CheckSigFromStack for non-interactive setup
- [ ] **Merkle Tree CET Templates**: Replace individual CETs with CTV templates encoded in Taproot merkle tree leaves
- [ ] **Non-Interactive Protocol**: Eliminate adaptor signature exchange by pre-committing all outcomes in funding transaction

#### Current Architecture Improvements

- [ ] **MuSig Key-Path Spending**: Implement key-path spending with MuSig adaptor signatures for maximum privacy (no script revelation)
- [ ] **Numerical Contract Support**: Extend beyond enumeration to support range-based outcomes
- [ ] **Collaborative Transaction Building**: Implement PSBT-based collaborative transaction construction

#### Advanced Features

- [ ] **Advanced Oracle Features**: Support for multi-oracle thresholds and complex attestation schemes
- [ ] **Signature Aggregation**: Explore cross-input signature aggregation for improved efficiency
- [ ] **Lightning Network Integration**: Research integration with Lightning channels for off-chain DLC settlement
- [ ] **Multi-Party Contracts**: Extend to support more than two participants
- [ ] **Optimized Script Paths**: Investigate alternative script constructions for specific use cases

## Dependencies and Limitations

### Schnorr Adaptor Signatures

This implementation uses [`schnorr-fun`](https://github.com/LLFourn/secp256k1-zkp-schnorr-fun) for adaptor signature operations instead of the traditional `secp256k1-zkp` + `rust-bitcoin` combination. This is due to:

- **Waiting for upstream support**: The official Schnorr adaptor signature module is pending in [secp256k1-zkp PR #299](https://github.com/BlockstreamResearch/secp256k1-zkp/pull/299)
- **Research flexibility**: `schnorr-fun` provides more experimental features suitable for research
- **API completeness**: Full adaptor signature API available immediately

### Current Limitations

1. **Enumeration Contracts Only**: Numerical contracts are not yet implemented
2. **No CET Spending**: Contract execution transactions can be created but not yet spent
3. **Missing Refund Logic**: Refund transactions for timeout scenarios not implemented
4. **Single Oracle**: Currently supports single oracle attestations only

## Usage Example

```rust
use taproot_dlc::{DlcParty, wallet::TaprootWallet};
use bitcoin::{Amount, FeeRate};

// Create participants
let alice_wallet = TaprootWallet::wallet();
let bob_wallet = TaprootWallet::wallet();

let alice = DlcParty::new(alice_wallet, blockchain, true, "ALICE".to_string());
let bob = DlcParty::new(bob_wallet, blockchain, false, "BOB".to_string());

// Create and execute DLC
let offer = alice.offer_dlc(
    contract_info,
    Amount::from_btc(0.5).unwrap(),
    Amount::ONE_BTC,
    FeeRate::from_sat_per_vb_unchecked(1),
).await?;

let accept = bob.accept_dlc(offer).await?;
let signed = alice.sign_dlc(accept).await?;
let funding_tx = bob.verify_sign_and_broadcast(signed).await?;
```

## Research Applications

This implementation serves as a foundation for researching:

1. **Covenant-Based Non-Interactive DLCs**: The transformative potential of CTV + CSFS for eliminating interactive setup protocols
2. **Merkle Tree Architecture**: How Taproot's tree structure can encode all contract outcomes in a single funding transaction
3. **Privacy-Preserving Contracts**: How Taproot's privacy features affect DLC observability
4. **Script-Path vs Key-Path Spending**: Current script-path implementation vs future MuSig key-path spending for ultimate privacy
5. **Interactive vs Non-Interactive Protocols**: Comparing current adaptor signature protocols with covenant-based approaches
6. **Scalability Improvements**: Transaction size reductions and efficiency gains through tree-based outcome encoding
7. **Advanced Contract Structures**: New contract types enabled by Taproot scripting
8. **Oracle Protocol Evolution**: How modern signature schemes can improve oracle security
9. **Cross-Layer Integration**: Interactions between DLCs and Lightning Network

## Building and Testing

```bash
# Build the project
cargo build

# Run tests (requires Bitcoin Core and Esplora)
cargo test

# Run the demo
cargo run --bin main
```

### Test Environment Setup

The tests require:

- Bitcoin Core running in regtest mode on port 18443
- Esplora API server on port 30000
- RPC credentials: `ddk:ddk`

## Contributing

This is a research project exploring the boundaries of what's possible with Taproot DLCs. Contributions are welcome, particularly in:

- Implementing missing features from the roadmap
- Optimizing script constructions
- Adding support for advanced oracle schemes
- Improving test coverage and documentation

## References

- [DLC Specification](https://github.com/discreetlogcontracts/dlcspecs)
- [BIP 341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [Schnorr Adaptor Signatures](https://github.com/BlockstreamResearch/secp256k1-zkp/pull/299)
- [Lightning Labs DLC Research](https://lightning.engineering/posts/2020-06-25-lnd-dlc/)

## License

This project is licensed under [LICENSE] - see the LICENSE file for details.

---

_This is a research implementation and should not be used in production environments. The techniques demonstrated here are experimental and may have security implications that require further analysis._
