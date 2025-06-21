
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

(define-constant ERR-BREACH-NOT-FOUND (err u106))
(define-constant ERR-INVALID-BREACH-STATUS (err u107))
(define-constant ERR-CANNOT-REPORT-OWN-BREACH (err u108))

(define-data-var breach-counter uint u0)

(define-map breach-reports
    uint
    {
        nda-id: uint,
        reporter: principal,
        accused: principal,
        description: (string-ascii 500),
        evidence-hash: (buff 32),
        status: (string-ascii 20),
        reported-at: uint,
        resolved-at: (optional uint),
        resolution: (optional (string-ascii 300))
    }
)

(define-map nda-breaches
    { nda-id: uint, accused: principal }
    (list 10 uint)
)

(define-public (report-breach 
    (nda-id uint) 
    (accused principal) 
    (description (string-ascii 500)) 
    (evidence-hash (buff 32)))
    (let
        (
            (nda (unwrap! (map-get? ndas nda-id) ERR-NDA-NOT-FOUND))
            (new-breach-id (+ (var-get breach-counter) u1))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
            (existing-breaches (default-to (list) (map-get? nda-breaches { nda-id: nda-id, accused: accused })))
        )
        (asserts! (has-signed nda-id tx-sender) ERR-NOT-AUTHORIZED)
        (asserts! (has-signed nda-id accused) ERR-NOT-AUTHORIZED)
        (asserts! (not (is-eq tx-sender accused)) ERR-CANNOT-REPORT-OWN-BREACH)
        
        (map-set breach-reports new-breach-id {
            nda-id: nda-id,
            reporter: tx-sender,
            accused: accused,
            description: description,
            evidence-hash: evidence-hash,
            status: "pending",
            reported-at: current-time,
            resolved-at: none,
            resolution: none
        })
        
        (map-set nda-breaches 
            { nda-id: nda-id, accused: accused }
            (unwrap-panic (as-max-len? (append existing-breaches new-breach-id) u10))
        )
        
        (var-set breach-counter new-breach-id)
        (ok new-breach-id)
    )
)

(define-public (resolve-breach 
    (breach-id uint) 
    (resolution (string-ascii 300)))
    (let
        (
            (breach (unwrap! (map-get? breach-reports breach-id) ERR-BREACH-NOT-FOUND))
            (nda (unwrap! (map-get? ndas (get nda-id breach)) ERR-NDA-NOT-FOUND))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (is-eq tx-sender (get creator nda)) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status breach) "pending") ERR-INVALID-BREACH-STATUS)
        
        (map-set breach-reports breach-id (merge breach {
            status: "resolved",
            resolved-at: (some current-time),
            resolution: (some resolution)
        }))
        (ok true)
    )
)

(define-public (dismiss-breach (breach-id uint))
    (let
        (
            (breach (unwrap! (map-get? breach-reports breach-id) ERR-BREACH-NOT-FOUND))
            (nda (unwrap! (map-get? ndas (get nda-id breach)) ERR-NDA-NOT-FOUND))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (is-eq tx-sender (get creator nda)) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status breach) "pending") ERR-INVALID-BREACH-STATUS)
        
        (map-set breach-reports breach-id (merge breach {
            status: "dismissed",
            resolved-at: (some current-time),
            resolution: (some "Breach report dismissed by NDA creator")
        }))
        (ok true)
    )
)

(define-read-only (get-breach-report (breach-id uint))
    (ok (map-get? breach-reports breach-id))
)

(define-read-only (get-nda-breaches (nda-id uint) (accused principal))
    (ok (map-get? nda-breaches { nda-id: nda-id, accused: accused }))
)

(define-read-only (get-breach-counter)
    (ok (var-get breach-counter))
)

(define-read-only (has-pending-breaches (nda-id uint) (accused principal))
    (let
        (
            (breach-ids (default-to (list) (map-get? nda-breaches { nda-id: nda-id, accused: accused })))
        )
        (> (len (filter check-pending-breach breach-ids)) u0)
    )
)

(define-private (check-pending-breach (breach-id uint))
    (match (map-get? breach-reports breach-id)
        breach (is-eq (get status breach) "pending")
        false
    )
)