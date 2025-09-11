
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

;; === NDA AUTO-RENEWAL AND EXPIRATION MANAGEMENT SYSTEM ===

;; Error constants for renewal system
(define-constant ERR-RENEWAL-NOT-FOUND (err u113))
(define-constant ERR-RENEWAL-ALREADY-VOTED (err u114))
(define-constant ERR-RENEWAL-EXPIRED (err u115))
(define-constant ERR-INVALID-NOTIFICATION-PERIOD (err u116))
(define-constant ERR-NDA-ALREADY-EXPIRED (err u117))
(define-constant ERR-INSUFFICIENT-VOTES (err u118))

;; Data variables for renewal system
(define-data-var renewal-counter uint u0)

;; Maps for renewal functionality
(define-map nda-renewal-settings
    uint ;; nda-id
    {
        auto-renewal-enabled: bool,
        notification-period: uint, ;; days before expiration to notify
        grace-period: uint, ;; days after expiration to allow renewal
        minimum-votes-required: uint, ;; minimum votes needed for renewal
        new-duration: uint ;; default renewal duration in seconds
    }
)

(define-map renewal-proposals
    uint ;; renewal-id
    {
        nda-id: uint,
        proposer: principal,
        new-expiration: uint,
        new-terms-hash: (optional (buff 32)), ;; hash of updated terms if any
        status: (string-ascii 20), ;; "active", "approved", "rejected", "expired"
        created-at: uint,
        voting-deadline: uint,
        votes-for: uint,
        votes-against: uint,
        executed-at: (optional uint)
    }
)

(define-map renewal-votes
    { renewal-id: uint, voter: principal }
    {
        vote: bool, ;; true for yes, false for no
        voted-at: uint,
        vote-weight: uint ;; currently always 1, future extensibility
    }
)

(define-map nda-renewal-history
    uint ;; nda-id
    (list 20 uint) ;; list of renewal-ids
)

(define-map expiration-notifications
    uint ;; nda-id
    {
        last-notification-sent: uint,
        notification-count: uint,
        signers-notified: (list 50 principal)
    }
)

;; Configure renewal settings for an NDA
(define-public (configure-nda-renewal 
    (nda-id uint)
    (auto-renewal-enabled bool)
    (notification-period uint)
    (grace-period uint)
    (minimum-votes-required uint)
    (new-duration uint))
    (let
        (
            (nda (unwrap! (map-get? ndas nda-id) ERR-NDA-NOT-FOUND))
            (current-owner (get-nda-owner nda-id))
        )
        ;; Only current owner can configure renewal settings
        (asserts! (is-eq tx-sender current-owner) ERR-NOT-AUTHORIZED)
        ;; Notification period should be reasonable (1-90 days)
        (asserts! (and (>= notification-period u1) (<= notification-period u90)) ERR-INVALID-NOTIFICATION-PERIOD)
        ;; Grace period should be reasonable (1-30 days)
        (asserts! (and (>= grace-period u1) (<= grace-period u30)) ERR-INVALID-NOTIFICATION-PERIOD)
        
        (map-set nda-renewal-settings nda-id {
            auto-renewal-enabled: auto-renewal-enabled,
            notification-period: notification-period,
            grace-period: grace-period,
            minimum-votes-required: minimum-votes-required,
            new-duration: new-duration
        })
        (ok true)
    )
)

;; Propose renewal for an NDA
(define-public (propose-nda-renewal 
    (nda-id uint) 
    (new-expiration uint)
    (new-terms-hash (optional (buff 32))))
    (let
        (
            (nda (unwrap! (map-get? ndas nda-id) ERR-NDA-NOT-FOUND))
            (renewal-settings (map-get? nda-renewal-settings nda-id))
            (new-renewal-id (+ (var-get renewal-counter) u1))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
            (voting-deadline (+ current-time u864000)) ;; 10 days voting period
            (existing-renewals (default-to (list) (map-get? nda-renewal-history nda-id)))
        )
        ;; Check if proposer has signed the NDA
        (asserts! (has-signed nda-id tx-sender) ERR-NOT-AUTHORIZED)
        ;; Check if NDA hasn't expired beyond grace period
        (match renewal-settings
            settings (asserts! 
                (< current-time (+ (get expires-at nda) (* (get grace-period settings) u86400)))
                ERR-NDA-ALREADY-EXPIRED)
            ;; If no renewal settings, use default 7-day grace period
            (asserts! (< current-time (+ (get expires-at nda) u604800)) ERR-NDA-ALREADY-EXPIRED)
        )
        ;; New expiration should be in the future
        (asserts! (> new-expiration current-time) ERR-INVALID-STATUS)
        
        (map-set renewal-proposals new-renewal-id {
            nda-id: nda-id,
            proposer: tx-sender,
            new-expiration: new-expiration,
            new-terms-hash: new-terms-hash,
            status: "active",
            created-at: current-time,
            voting-deadline: voting-deadline,
            votes-for: u0,
            votes-against: u0,
            executed-at: none
        })
        
        ;; Update renewal history
        (map-set nda-renewal-history nda-id 
            (unwrap-panic (as-max-len? (append existing-renewals new-renewal-id) u20)))
        
        (var-set renewal-counter new-renewal-id)
        (ok new-renewal-id)
    )
)

;; Vote on a renewal proposal
(define-public (vote-on-renewal (renewal-id uint) (vote bool))
    (let
        (
            (proposal (unwrap! (map-get? renewal-proposals renewal-id) ERR-RENEWAL-NOT-FOUND))
            (nda-id (get nda-id proposal))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
            (vote-key { renewal-id: renewal-id, voter: tx-sender })
        )
        ;; Check if voter has signed the NDA
        (asserts! (has-signed nda-id tx-sender) ERR-NOT-AUTHORIZED)
        ;; Check if proposal is still active
        (asserts! (is-eq (get status proposal) "active") ERR-INVALID-STATUS)
        ;; Check if voting period hasn't expired
        (asserts! (< current-time (get voting-deadline proposal)) ERR-RENEWAL-EXPIRED)
        ;; Check if voter hasn't already voted
        (asserts! (is-none (map-get? renewal-votes vote-key)) ERR-RENEWAL-ALREADY-VOTED)
        
        ;; Record the vote
        (map-set renewal-votes vote-key {
            vote: vote,
            voted-at: current-time,
            vote-weight: u1
        })
        
        ;; Update vote counts
        (if vote
            (map-set renewal-proposals renewal-id 
                (merge proposal { votes-for: (+ (get votes-for proposal) u1) }))
            (map-set renewal-proposals renewal-id 
                (merge proposal { votes-against: (+ (get votes-against proposal) u1) }))
        )
        
        (ok true)
    )
)

;; Execute renewal if conditions are met
(define-public (execute-renewal (renewal-id uint))
    (let
        (
            (proposal (unwrap! (map-get? renewal-proposals renewal-id) ERR-RENEWAL-NOT-FOUND))
            (nda-id (get nda-id proposal))
            (nda (unwrap! (map-get? ndas nda-id) ERR-NDA-NOT-FOUND))
            (renewal-settings (map-get? nda-renewal-settings nda-id))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
            (votes-for (get votes-for proposal))
            (votes-against (get votes-against proposal))
            (total-votes (+ votes-for votes-against))
        )
        ;; Check if proposal is still active
        (asserts! (is-eq (get status proposal) "active") ERR-INVALID-STATUS)
        ;; Check if voting deadline has passed
        (asserts! (>= current-time (get voting-deadline proposal)) ERR-INVALID-STATUS)
        
        ;; Determine if renewal should be approved
        (let
            (
                (min-votes-required (match renewal-settings
                    settings (get minimum-votes-required settings)
                    u2)) ;; default minimum
                (approval-threshold (if (> total-votes u0) (/ (* votes-for u100) total-votes) u0))
            )
            ;; Require minimum votes and majority approval (>50%)
            (if (and (>= total-votes min-votes-required) (> approval-threshold u50))
                ;; Approve and execute renewal
                (begin
                    (map-set renewal-proposals renewal-id 
                        (merge proposal { 
                            status: "approved",
                            executed-at: (some current-time)
                        }))
                    ;; Update NDA expiration
                    (map-set ndas nda-id 
                        (merge nda { 
                            expires-at: (get new-expiration proposal),
                            status: "active"
                        }))
                    (ok "approved"))
                ;; Reject renewal
                (begin
                    (map-set renewal-proposals renewal-id 
                        (merge proposal { status: "rejected" }))
                    (ok "rejected"))
            )
        )
    )
)

;; Check if NDA needs renewal notification
(define-public (check-renewal-notification (nda-id uint))
    (let
        (
            (nda (unwrap! (map-get? ndas nda-id) ERR-NDA-NOT-FOUND))
            (renewal-settings (map-get? nda-renewal-settings nda-id))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
            (notification-info (map-get? expiration-notifications nda-id))
        )
        (match renewal-settings
            settings (let
                (
                    (notification-threshold (- (get expires-at nda) 
                        (* (get notification-period settings) u86400)))
                    (should-notify (and 
                        (>= current-time notification-threshold)
                        (< current-time (get expires-at nda))))
                )
                (if should-notify
                    (begin
                        ;; Update notification record
                        (map-set expiration-notifications nda-id {
                            last-notification-sent: current-time,
                            notification-count: (match notification-info
                                info (+ (get notification-count info) u1)
                                u1),
                            signers-notified: (list) ;; Would contain list of notified signers
                        })
                        (ok "notification-sent"))
                    (ok "no-notification-needed")))
            (ok "no-renewal-settings")
        )
    )
)

;; Read-only functions for renewal system
(define-read-only (get-renewal-settings (nda-id uint))
    (ok (map-get? nda-renewal-settings nda-id))
)

(define-read-only (get-renewal-proposal (renewal-id uint))
    (ok (map-get? renewal-proposals renewal-id))
)

(define-read-only (get-renewal-vote (renewal-id uint) (voter principal))
    (ok (map-get? renewal-votes { renewal-id: renewal-id, voter: voter }))
)

(define-read-only (get-nda-renewal-history (nda-id uint))
    (ok (map-get? nda-renewal-history nda-id))
)

(define-read-only (get-expiration-notification-info (nda-id uint))
    (ok (map-get? expiration-notifications nda-id))
)

(define-read-only (get-renewal-counter)
    (ok (var-get renewal-counter))
)

;; Check if NDA is within renewal period
(define-read-only (is-nda-renewable (nda-id uint))
    (match (map-get? ndas nda-id)
        nda (let
            (
                (current-time (unwrap-panic (get-stacks-block-info? time u0)))
                (renewal-settings (map-get? nda-renewal-settings nda-id))
            )
            (match renewal-settings
                settings (< current-time (+ (get expires-at nda) (* (get grace-period settings) u86400)))
                (< current-time (+ (get expires-at nda) u604800)) ;; default 7-day grace
            ))
        false
    )
)

(define-constant ERR-TRANSFER-NOT-FOUND (err u109))
(define-constant ERR-TRANSFER-ALREADY-PROCESSED (err u110))
(define-constant ERR-INVALID-TRANSFER-STATUS (err u111))
(define-constant ERR-CANNOT-TRANSFER-TO-SELF (err u112))

(define-data-var transfer-counter uint u0)

(define-map nda-transfers
    uint
    {
        nda-id: uint,
        from-owner: principal,
        to-owner: principal,
        transfer-reason: (string-ascii 200),
        status: (string-ascii 20),
        proposed-at: uint,
        accepted-at: (optional uint),
        rejected-at: (optional uint)
    }
)

(define-map nda-ownership
    uint
    {
        current-owner: principal,
        original-creator: principal,
        last-transfer-id: (optional uint),
        transfer-count: uint
    }
)

(define-map pending-transfers
    { nda-id: uint, to-owner: principal }
    uint
)

(define-public (propose-nda-transfer 
    (nda-id uint) 
    (new-owner principal) 
    (reason (string-ascii 200)))
    (let
        (
            (nda (unwrap! (map-get? ndas nda-id) ERR-NDA-NOT-FOUND))
            (current-owner (get-nda-owner nda-id))
            (new-transfer-id (+ (var-get transfer-counter) u1))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (is-eq tx-sender current-owner) ERR-NOT-AUTHORIZED)
        (asserts! (not (is-eq current-owner new-owner)) ERR-CANNOT-TRANSFER-TO-SELF)
        (asserts! (is-none (map-get? pending-transfers { nda-id: nda-id, to-owner: new-owner })) ERR-INVALID-TRANSFER-STATUS)
        
        (map-set nda-transfers new-transfer-id {
            nda-id: nda-id,
            from-owner: current-owner,
            to-owner: new-owner,
            transfer-reason: reason,
            status: "pending",
            proposed-at: current-time,
            accepted-at: none,
            rejected-at: none
        })
        
        (map-set pending-transfers { nda-id: nda-id, to-owner: new-owner } new-transfer-id)
        (var-set transfer-counter new-transfer-id)
        (ok new-transfer-id)
    )
)

(define-public (accept-nda-transfer (transfer-id uint))
    (let
        (
            (transfer (unwrap! (map-get? nda-transfers transfer-id) ERR-TRANSFER-NOT-FOUND))
            (nda-id (get nda-id transfer))
            (from-owner (get from-owner transfer))
            (to-owner (get to-owner transfer))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
            (current-ownership (default-to 
                { current-owner: from-owner, original-creator: from-owner, last-transfer-id: none, transfer-count: u0 }
                (map-get? nda-ownership nda-id)))
        )
        (asserts! (is-eq tx-sender to-owner) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status transfer) "pending") ERR-TRANSFER-ALREADY-PROCESSED)
        
        (map-set nda-transfers transfer-id (merge transfer {
            status: "accepted",
            accepted-at: (some current-time)
        }))
        
        (map-set nda-ownership nda-id (merge current-ownership {
            current-owner: to-owner,
            last-transfer-id: (some transfer-id),
            transfer-count: (+ (get transfer-count current-ownership) u1)
        }))
        
        (map-delete pending-transfers { nda-id: nda-id, to-owner: to-owner })
        (ok true)
    )
)

(define-public (reject-nda-transfer (transfer-id uint))
    (let
        (
            (transfer (unwrap! (map-get? nda-transfers transfer-id) ERR-TRANSFER-NOT-FOUND))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (is-eq tx-sender (get to-owner transfer)) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status transfer) "pending") ERR-TRANSFER-ALREADY-PROCESSED)
        
        (map-set nda-transfers transfer-id (merge transfer {
            status: "rejected",
            rejected-at: (some current-time)
        }))
        
        (map-delete pending-transfers { nda-id: (get nda-id transfer), to-owner: (get to-owner transfer) })
        (ok true)
    )
)

(define-private (get-nda-owner (nda-id uint))
    (match (map-get? nda-ownership nda-id)
        ownership (get current-owner ownership)
        (match (map-get? ndas nda-id)
            nda (get creator nda)
            (get creator (unwrap-panic (map-get? ndas nda-id)))
        )
    )
)

(define-public (revoke-nda-v2 (nda-id uint))
    (let
        (
            (nda (unwrap! (map-get? ndas nda-id) ERR-NDA-NOT-FOUND))
            (current-owner (get-nda-owner nda-id))
        )
        (asserts! (is-eq tx-sender current-owner) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status nda) "active") ERR-INVALID-STATUS)
        
        (map-set ndas nda-id (merge nda { status: "revoked" }))
        (ok true)
    )
)

(define-public (resolve-breach-v2 
    (breach-id uint) 
    (resolution (string-ascii 300)))
    (let
        (
            (breach (unwrap! (map-get? breach-reports breach-id) ERR-BREACH-NOT-FOUND))
            (nda-id (get nda-id breach))
            (current-owner (get-nda-owner nda-id))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (is-eq tx-sender current-owner) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status breach) "pending") ERR-INVALID-BREACH-STATUS)
        
        (map-set breach-reports breach-id (merge breach {
            status: "resolved",
            resolved-at: (some current-time),
            resolution: (some resolution)
        }))
        (ok true)
    )
)

(define-public (dismiss-breach-v2 (breach-id uint))
    (let
        (
            (breach (unwrap! (map-get? breach-reports breach-id) ERR-BREACH-NOT-FOUND))
            (nda-id (get nda-id breach))
            (current-owner (get-nda-owner nda-id))
            (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        )
        (asserts! (is-eq tx-sender current-owner) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status breach) "pending") ERR-INVALID-BREACH-STATUS)
        
        (map-set breach-reports breach-id (merge breach {
            status: "dismissed",
            resolved-at: (some current-time),
            resolution: (some "Breach report dismissed by current NDA owner")
        }))
        (ok true)
    )
)

(define-read-only (get-nda-transfer (transfer-id uint))
    (ok (map-get? nda-transfers transfer-id))
)

(define-read-only (get-nda-ownership-info (nda-id uint))
    (ok (map-get? nda-ownership nda-id))
)

(define-read-only (get-pending-transfer (nda-id uint) (to-owner principal))
    (ok (map-get? pending-transfers { nda-id: nda-id, to-owner: to-owner }))
)

(define-read-only (get-current-owner (nda-id uint))
    (ok (get-nda-owner nda-id))
)

(define-read-only (get-transfer-counter)
    (ok (var-get transfer-counter))
)

