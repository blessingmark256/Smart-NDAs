# Smart NDAs - Blockchain-Based Legal Agreements

A decentralized smart contract for creating and managing Non-Disclosure Agreements (NDAs) on the Stacks blockchain.

## Features

- Create NDAs with title, content, and expiration date
- Sign NDAs with cryptographic signatures
- Revoke active NDAs (creator only)
- Query NDA details and signature status
- Timestamp-based validation
- Immutable record keeping

## Contract Functions

### Public Functions

1. `create-nda`: Create a new NDA
   - Parameters: title (string-ascii), content (string-ascii), expires-at (uint)
   - Returns: NDA ID

2. `sign-nda`: Sign an existing NDA
   - Parameters: nda-id (uint), signature-hash (buff 32)
   - Returns: boolean

3. `revoke-nda`: Revoke an active NDA
   - Parameters: nda-id (uint)
   - Returns: boolean

### Read-Only Functions

1. `get-nda`: Get NDA details
2. `get-signature`: Get signature details
3. `has-signed`: Check if principal has signed
4. `get-nda-counter`: Get total NDAs created

## Error Codes

- u100: Not authorized
- u101: Already signed
- u102: NDA not found
- u103: Invalid status

## Usage Example

```clarity
;; Create new NDA
(contract-call? .smart-ndas create-nda "Project X NDA" "Confidentiality terms..." u1234567890)

;; Sign NDA
(contract-call? .smart-ndas sign-nda u1 0x...)

;; Check NDA details
(contract-call? .smart-ndas get-nda u1)
```