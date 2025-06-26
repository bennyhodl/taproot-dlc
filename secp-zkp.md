# Migration from schnorr_fun to secp256k1-zkp Schnorr Adaptors

## Current Dependencies Analysis

### schnorr_fun Dependencies (TO BE REMOVED)

```rust
// Current imports that need to be replaced
use schnorr_fun::adaptor::{Adaptor, EncryptedSign};
use schnorr_fun::fun::marker::{NonZero, Normal, Public, Secret};
use schnorr_fun::Message;
use schnorr_fun::{
    adaptor::EncryptedSignature,
    fun::{marker::EvenY, KeyPair, Point, Scalar},
    nonce::{GlobalRng, Synthetic},
    Schnorr, Signature,
};
```

### secp256k1-zkp Dependencies (TO BE ADDED)

```rust
// New imports to replace schnorr_fun
use secp256k1_zkp::{
    SchnorrAdaptorPreSignature,
    Keypair,           // Replace schnorr_fun::KeyPair
    SecretKey,         // For adaptor secret handling
    PublicKey,         // For adaptor point handling
    Message,           // Replace schnorr_fun::Message
    Secp256k1, All,    // Context handling
    schnorr::Signature as SchnorrSignature, // Replace schnorr_fun::Signature
};
```

## Step 1: DlcParty Struct Refactoring

### Current Implementation

```rust
pub struct DlcParty<B> {
    secp: Secp256k1<All>,
    // ❌ schnorr_fun context - TO BE REMOVED
    context: Schnorr<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>>,
    // ❌ schnorr_fun keypair - TO BE REPLACED
    keypair: KeyPair<EvenY>,
    funding_pubkey: XOnlyPublicKey,
    wallet: TaprootWallet,
    blockchain: B,
    is_offerer: bool,
    name: String,
}
```

### Refactored Implementation

```rust
pub struct DlcParty<B> {
    secp: Secp256k1<All>,
    // ✅ Use secp256k1-zkp Keypair directly
    keypair: Keypair,
    funding_pubkey: XOnlyPublicKey,
    wallet: TaprootWallet,
    blockchain: B,
    is_offerer: bool,
    name: String,
}
```

**Why this change:**

- Eliminates the `schnorr_fun::Schnorr` context dependency
- Uses native secp256k1-zkp types throughout
- Simplifies the struct by removing the intermediate context layer

## Step 2: Constructor Migration

### Current Implementation

```rust
pub fn new(wallet: TaprootWallet, blockchain: B, is_offerer: bool, name: String) -> Self {
    let secp = Secp256k1::new();
    // ❌ schnorr_fun context creation
    let nonce_gen = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default();
    let context = Schnorr::<Sha256, _>::new(nonce_gen);

    // ❌ schnorr_fun keypair generation
    let keypair = context.new_keypair(Scalar::random(&mut thread_rng()));
    let funding_pubkey = XOnlyPublicKey::from_slice(&keypair.public_key().to_xonly_bytes()).unwrap();

    Self {
        secp, context, keypair, funding_pubkey, wallet, blockchain, is_offerer, name,
    }
}
```

### Refactored Implementation

```rust
pub fn new(wallet: TaprootWallet, blockchain: B, is_offerer: bool, name: String) -> Self {
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    // ✅ Use secp256k1-zkp keypair generation
    let keypair = Keypair::new(&secp, &mut rng);
    let (funding_pubkey, _parity) = keypair.x_only_public_key();

    debug!("{}: Generated funding pubkey: {:?}", name, funding_pubkey);

    Self {
        secp, keypair, funding_pubkey, wallet, blockchain, is_offerer, name,
    }
}
```

**Why this change:**

- Uses native secp256k1-zkp key generation
- Eliminates schnorr_fun Scalar and context dependencies
- More straightforward and follows secp256k1 patterns

## Step 3: Adaptor Signature Creation Migration

### Current Implementation

```rust
async fn create_cet_adaptor_signatures(
    &self,
    // ... parameters
) -> Vec<EncryptedSignature> { // ❌ schnorr_fun type
    // ... setup code
    for (i, outcome) in enumeration.outcome_payouts.iter().enumerate() {
        // ... CET building

        let nonce = announcement.oracle_event.oracle_nonces[i].clone();
        // ❌ schnorr_fun conversion
        let oracle_point = convert_xonly_to_normal_point(&nonce);

        let sighash = create_sighash_msg(/* ... */).await;
        let bytes = sighash.as_raw_hash().as_byte_array();
        // ❌ schnorr_fun Message type
        let message = Message::<Secret>::raw(bytes);

        // ❌ schnorr_fun context method
        let encrypted_signature = self.context.encrypted_sign(&self.keypair, &oracle_point, message);
        sigs.push(encrypted_signature);
    }
}
```

### Refactored Implementation

```rust
async fn create_cet_adaptor_signatures(
    &self,
    // ... parameters
) -> Vec<SchnorrAdaptorPreSignature> { // ✅ secp256k1-zkp type
    // ... setup code
    for (i, outcome) in enumeration.outcome_payouts.iter().enumerate() {
        // ... CET building

        let nonce = announcement.oracle_event.oracle_nonces[i].clone();
        // ✅ Convert XOnlyPublicKey to PublicKey for adaptor point
        let oracle_adaptor_point = PublicKey::from_x_only_public_key(nonce, bitcoin::key::Parity::Even);

        let sighash = create_sighash_msg(/* ... */).await;
        let bytes = sighash.as_raw_hash().as_byte_array();
        // ✅ Use secp256k1-zkp Message
        let message = Message::from_digest(bytes);

        // ✅ Use SchnorrAdaptorPreSignature static method
        let adaptor_presig = SchnorrAdaptorPreSignature::presign(
            &self.secp,
            &message,
            &self.keypair,
            &oracle_adaptor_point,
        );

        sigs.push(adaptor_presig);
    }
    sigs
}
```

**Why this change:**

- Uses `SchnorrAdaptorPreSignature::presign()` instead of context method
- Native secp256k1-zkp Message type from digest
- Eliminates custom point conversion utilities
- Cleaner, more direct API usage

## Step 4: Adaptor Signature Verification Migration

### Current Implementation

```rust
async fn verify_adaptor_signatures(
    &self,
    // ... parameters
    sigs: &[EncryptedSignature], // ❌ schnorr_fun type
    // ... more parameters
) -> Result<(), TaprootDlcError> {
    for (i, signature) in sigs.iter().enumerate() {
        let nonce = announcement.oracle_event.oracle_nonces[i].clone();
        // ❌ schnorr_fun conversion
        let oracle_point = convert_xonly_to_normal_point(&nonce);

        // ... CET building and sighash creation
        let bytes = sighash.as_raw_hash().as_byte_array();
        // ❌ schnorr_fun Message type
        let message = Message::<Secret>::raw(bytes);

        // ❌ schnorr_fun Point conversion
        let verify_key = if self.is_offerer {
            Point::<EvenY>::from_xonly_bytes(accept.accept_params.fund_pubkey.serialize()).unwrap()
        } else {
            Point::<EvenY>::from_xonly_bytes(accept.offer.offer_params.fund_pubkey.serialize()).unwrap()
        };

        // ❌ schnorr_fun context verification
        if !self.context.verify_encrypted_signature(&verify_key, &oracle_point, message, signature) {
            return Err(TaprootDlcError::InvalidAdaptorSignature);
        }
    }
    Ok(())
}
```

### Refactored Implementation

```rust
async fn verify_adaptor_signatures(
    &self,
    // ... parameters
    sigs: &[SchnorrAdaptorPreSignature], // ✅ secp256k1-zkp type
    // ... more parameters
) -> Result<(), TaprootDlcError> {
    for (i, presignature) in sigs.iter().enumerate() {
        let nonce = announcement.oracle_event.oracle_nonces[i].clone();
        // ✅ Convert to PublicKey for adaptor point
        let expected_oracle_point = PublicKey::from_x_only_public_key(nonce, bitcoin::key::Parity::Even);

        // ... CET building and sighash creation
        let bytes = sighash.as_raw_hash().as_byte_array();
        // ✅ Use secp256k1-zkp Message
        let message = Message::from_digest(bytes);

        // ✅ Get the counterparty's XOnlyPublicKey directly
        let verify_pubkey = if self.is_offerer {
            accept.accept_params.fund_pubkey
        } else {
            accept.offer.offer_params.fund_pubkey
        };

        // ✅ Extract adaptor point from pre-signature and verify it matches expected
        let extracted_adaptor = presignature.extract_adaptor(&message, &verify_pubkey)
            .map_err(|_| TaprootDlcError::InvalidAdaptorSignature)?;

        if extracted_adaptor != expected_oracle_point {
            error!("{}: Adaptor point mismatch", self.name);
            return Err(TaprootDlcError::InvalidAdaptorSignature);
        }
    }
    Ok(())
}
```

**Why this change:**

- Uses `extract_adaptor()` method to verify adaptor signatures
- Compares extracted adaptor point with expected oracle point
- Eliminates complex schnorr_fun Point conversions
- More explicit verification logic

## Step 5: Signature Decryption Migration

### Current Implementation

```rust
fn decrypt_adaptor_signature(
    &self,
    oracle_signature: Signature, // ❌ schnorr_fun type
    encrypted_signature: EncryptedSignature, // ❌ schnorr_fun type
) -> Signature { // ❌ schnorr_fun type
    // ❌ schnorr_fun secret extraction
    let s = oracle_signature.s.non_zero().unwrap().secret();
    // ❌ schnorr_fun context method
    self.context.decrypt_signature(s, encrypted_signature)
}
```

### Refactored Implementation

```rust
fn adapt_presignature_with_oracle_sig(
    &self,
    oracle_signature: SchnorrSignature, // ✅ secp256k1-zkp type
    adaptor_presignature: SchnorrAdaptorPreSignature, // ✅ secp256k1-zkp type
) -> Result<SchnorrSignature, TaprootDlcError> { // ✅ secp256k1-zkp type
    // ✅ Extract secret adaptor from oracle signature and pre-signature
    let secret_adaptor = adaptor_presignature.extract_secadaptor(&oracle_signature)
        .map_err(|_| TaprootDlcError::InvalidAdaptorSignature)?;

    // ✅ Adapt the pre-signature to create full signature
    let adapted_signature = adaptor_presignature.adapt(&secret_adaptor)
        .map_err(|_| TaprootDlcError::InvalidAdaptorSignature)?;

    Ok(adapted_signature)
}
```

**Why this change:**

- Uses `extract_secadaptor()` to get the secret from oracle signature
- Uses `adapt()` method to create the final signature
- Proper error handling with Result return type
- Eliminates manual secret extraction logic

## Step 6: CET Spending Migration

### Current Implementation

```rust
fn spend_cet(
    &self,
    // ... parameters
    oracle_signature: Signature, // ❌ schnorr_fun type
    counterparty_signature: EncryptedSignature, // ❌ schnorr_fun type
    encrypted_signature: EncryptedSignature, // ❌ schnorr_fun type
    // ... parameters
) -> Result<Transaction, TaprootDlcError> {
    // ❌ schnorr_fun decryption
    let my_sig = self.context.decrypt_signature(
        oracle_signature.s.non_zero().unwrap(),
        encrypted_signature
    );

    // ❌ schnorr_fun decryption
    let counterparty_sig = self.context.decrypt_signature(
        oracle_signature.s.non_zero().unwrap(),
        counterparty_signature,
    );

    // ... witness construction
}
```

### Refactored Implementation

```rust
fn spend_cet(
    &self,
    // ... parameters
    oracle_signature: SchnorrSignature, // ✅ secp256k1-zkp type
    counterparty_presignature: SchnorrAdaptorPreSignature, // ✅ secp256k1-zkp type
    my_presignature: SchnorrAdaptorPreSignature, // ✅ secp256k1-zkp type
    // ... parameters
) -> Result<Transaction, TaprootDlcError> {
    // ✅ Adapt both signatures using the oracle signature
    let my_sig = self.adapt_presignature_with_oracle_sig(oracle_signature, my_presignature)?;
    let counterparty_sig = self.adapt_presignature_with_oracle_sig(oracle_signature, counterparty_presignature)?;

    // ✅ Construct witness with adapted signatures
    let mut witness = Witness::new();
    witness.push(&my_sig.serialize());
    witness.push(&counterparty_sig.serialize());
    witness.push(Vec::new()); // OP_0 for multisig
    witness.push(funding_script.as_bytes());
    witness.push(&control_block.serialize());

    cet.input[0].witness = witness;
    Ok(cet.clone())
}
```

**Why this change:**

- Uses the new `adapt_presignature_with_oracle_sig()` helper method
- Both signatures are adapted consistently
- Cleaner error propagation

## Step 7: Remove Utility Functions

### Functions to Remove (No Longer Needed)

```rust
// ❌ DELETE - No longer needed with secp256k1-zkp
fn convert_xonly_to_normal_point(x_only_pk: &XOnlyPublicKey) -> Point<Normal, Public, NonZero> {
    // This entire function can be deleted
}

// ❌ DELETE - No longer needed with secp256k1-zkp
fn convert_keypair(keypair: &KeyPair<EvenY>, secp: &Secp256k1<All>) -> secp256k1_zkp::Keypair {
    // This entire function can be deleted
}
```

## Step 8: Updated Type Signatures

### Structure Field Updates

```rust
#[derive(Debug)]
pub struct DlcAccept {
    contract_id: [u8; 32],
    accept_params: PartyParams,
    // ✅ Updated type
    cet_adaptor_signatures: Vec<SchnorrAdaptorPreSignature>, // Was: Vec<EncryptedSignature>
    offer: DlcOffer,
}

#[derive(Debug)]
pub struct DlcSign {
    contract_id: [u8; 32],
    // ✅ Updated type
    cet_adaptor_signatures: Vec<SchnorrAdaptorPreSignature>, // Was: Vec<EncryptedSignature>
    pub funding_transaction: Transaction,
    pub funding_signatures: Vec<FundingSignature>,
    accept: DlcAccept,
}
```

## Step 9: Updated Import Block

### Final Import Block

```rust
// Remove all schnorr_fun imports
// Add these secp256k1-zkp imports:
use secp256k1_zkp::{
    All, Secp256k1, Keypair, SecretKey, PublicKey, Message,
    SchnorrAdaptorPreSignature,
    schnorr::Signature as SchnorrSignature,
};

// Keep existing imports:
use bitcoin::{
    Amount, FeeRate, OutPoint, Psbt, Script, ScriptBuf, Sequence, TapLeafHash, TapNodeHash,
    TapSighash, TapSighashType, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
// ... other existing imports
```

## Key Conceptual Differences

### schnorr_fun Paradigm (OLD)

- **"Encrypted Signature"** - You encrypt a signature with an adaptor point
- Context-based API with methods like `encrypted_sign()` and `decrypt_signature()`
- Custom type system with markers and Point types

### secp256k1-zkp Paradigm (NEW)

- **"Pre-Signature"** - You create a pre-signature that can be adapted
- Static methods on signature types like `presign()` and `adapt()`
- Native secp256k1 types throughout

## Benefits of Migration

1. **Consistency**: Uses the same library as rust-dlc's ECDSA adaptors
2. **Maintenance**: One less external dependency to maintain
3. **Performance**: Native secp256k1 implementation is highly optimized
4. **Compatibility**: Better integration with existing Bitcoin tooling
5. **Standards**: Follows established secp256k1 API patterns

## Migration Checklist

- [ ] Update imports to use secp256k1-zkp types
- [ ] Refactor DlcParty struct to remove schnorr_fun context
- [ ] Update constructor to use secp256k1-zkp key generation
- [ ] Replace adaptor signature creation with SchnorrAdaptorPreSignature::presign()
- [ ] Replace verification with extract_adaptor() and point comparison
- [ ] Replace decryption with adapt() method
- [ ] Update all type signatures throughout codebase
- [ ] Remove utility conversion functions
- [ ] Update tests to use new API
- [ ] Verify all functionality works with new implementation

This migration maintains the same cryptographic security properties while using the more standard secp256k1-zkp library that aligns with the broader Bitcoin ecosystem.
