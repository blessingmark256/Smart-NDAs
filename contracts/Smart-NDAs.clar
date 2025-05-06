
;; title: Smart-NDAs
;; version:
;; summary:
;; description:


(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-SIGNED (err u101))
(define-constant ERR-NDA-NOT-FOUND (err u102))
(define-constant ERR-INVALID-STATUS (err u103))

(define-data-var nda-counter uint u0)

(define-map ndas
    uint 
    {
        creator: principal,
        title: (string-ascii 100),
        content: (string-ascii 1000),
        status: (string-ascii 20),
        created-at: uint,
        expires-at: uint
    }
)

(define-map signatures
    { nda-id: uint, signer: principal }
    {
        signed-at: uint,
        signature-hash: (buff 32)
    }
)

(define-public (create-nda (title (string-ascii 100)) (content (string-ascii 1000)) (expires-at uint))
    (let
        (
            (new-id (+ (var-get nda-counter) u1))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (> expires-at current-time) ERR-INVALID-STATUS)
        (map-set ndas new-id {
            creator: tx-sender,
            title: title,
            content: content,
            status: "active",
            created-at: current-time,
            expires-at: expires-at
        })
        (var-set nda-counter new-id)
        (ok new-id)
    )
)

(define-public (sign-nda (nda-id uint) (signature-hash (buff 32)))
    (let
        (
            (nda (unwrap! (map-get? ndas nda-id) ERR-NDA-NOT-FOUND))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (is-eq (get status nda) "active") ERR-INVALID-STATUS)
        (asserts! (> (get expires-at nda) current-time) ERR-INVALID-STATUS)
        (asserts! (is-none (map-get? signatures { nda-id: nda-id, signer: tx-sender })) ERR-ALREADY-SIGNED)
        
        (map-set signatures { nda-id: nda-id, signer: tx-sender }
            {
                signed-at: current-time,
                signature-hash: signature-hash
            }
        )
        (ok true)
    )
)

(define-public (revoke-nda (nda-id uint))
    (let
        (
            (nda (unwrap! (map-get? ndas nda-id) ERR-NDA-NOT-FOUND))
        )
         (asserts! (is-eq tx-sender (get creator nda)) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status nda) "active") ERR-INVALID-STATUS)
        
        (map-set ndas nda-id (merge nda { status: "revoked" }))
        (ok true)
    )
)

(define-read-only (get-nda (nda-id uint))
    (ok (map-get? ndas nda-id))
)

(define-read-only (get-signature (nda-id uint) (signer principal))
    (ok (map-get? signatures { nda-id: nda-id, signer: signer }))
)

(define-read-only (has-signed (nda-id uint) (signer principal))
    (is-some (map-get? signatures { nda-id: nda-id, signer: signer }))
)

(define-read-only (get-nda-counter)
    (ok (var-get nda-counter))
)


(define-constant ERR-REQUIRED-SIGNERS-MISSING (err u104))

(define-map required-signers
    uint
    (list 50 principal)
)

(define-public (create-nda-with-required-signers 
    (title (string-ascii 100)) 
    (content (string-ascii 1000)) 
    (expires-at uint)
    (signers (list 50 principal)))
    (let
        (
            (new-id (+ (var-get nda-counter) u1))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (> expires-at current-time) ERR-INVALID-STATUS)
        (map-set ndas new-id {
            creator: tx-sender,
            title: title,
            content: content,
            status: "pending",
            created-at: current-time,
            expires-at: expires-at
        })
        (map-set required-signers new-id signers)
        (var-set nda-counter new-id)
        (ok new-id)
    )
)

(define-private (check-signer (signer principal) (all-signed bool) (id uint))
    (and all-signed (has-signed id signer))
)

(define-constant ERR-TEMPLATE-NOT-FOUND (err u105))

(define-map nda-templates
    uint
    {
        creator: principal,
        title: (string-ascii 100),
        content: (string-ascii 1000),
        created-at: uint
    }
)

(define-data-var template-counter uint u0)

(define-public (create-template 
    (title (string-ascii 100)) 
    (content (string-ascii 1000)))
    (let
        (
            (new-id (+ (var-get template-counter) u1))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (map-set nda-templates new-id {
            creator: tx-sender,
            title: title,
            content: content,
            created-at: current-time
        })
        (var-set template-counter new-id)
        (ok new-id)
    )
)

(define-public (create-nda-from-template 
    (template-id uint) 
    (expires-at uint))
    (let
        (
            (template (unwrap! (map-get? nda-templates template-id) ERR-TEMPLATE-NOT-FOUND))
            (new-id (+ (var-get nda-counter) u1))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (> expires-at current-time) ERR-INVALID-STATUS)
        (map-set ndas new-id {
            creator: tx-sender,
            title: (get title template),
            content: (get content template),
            status: "active",
            created-at: current-time,
            expires-at: expires-at
        })
        (var-set nda-counter new-id)
        (ok new-id)
    )
)