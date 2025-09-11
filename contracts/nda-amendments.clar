;; NDA Amendment & Version Control System
;; Manages amendments to existing NDAs with stakeholder voting and version tracking

;; Error constants  
(define-constant err-not-authorized (err u120))
(define-constant err-nda-not-found (err u121))
(define-constant err-amendment-not-found (err u122))
(define-constant err-already-voted (err u123))
(define-constant err-amendment-expired (err u124))
(define-constant err-amendment-already-executed (err u125))
(define-constant err-insufficient-votes (err u126))
(define-constant err-invalid-amendment-type (err u127))
(define-constant err-nda-not-active (err u128))
(define-constant err-version-not-found (err u129))

;; Data variables
(define-data-var amendment-id-nonce uint u0)
(define-data-var default-voting-period uint u604800) ;; 7 days in seconds

;; Amendment types
(define-constant amendment-type-content u1)
(define-constant amendment-type-duration u2)
(define-constant amendment-type-terms u3)
(define-constant amendment-type-signers u4)

;; Amendment proposals
(define-map amendment-proposals uint
  {
    nda-id: uint,
    proposer: principal,
    amendment-type: uint,
    new-content: (optional (string-ascii 1000)),
    new-expiration: (optional uint),
    additional-terms: (optional (string-ascii 500)),
    new-signers: (optional (list 10 principal)),
    description: (string-ascii 200),
    proposed-at: uint,
    voting-deadline: uint,
    votes-for: uint,
    votes-against: uint,
    status: (string-ascii 20), ;; pending, approved, rejected, executed
    executed-at: (optional uint)
  })

;; Amendment votes
(define-map amendment-votes (tuple (amendment-id uint) (voter principal))
  {
    vote: bool, ;; true for approve, false for reject
    voted-at: uint,
    rationale: (optional (string-ascii 200))
  })

;; NDA version history
(define-map nda-versions (tuple (nda-id uint) (version uint))
  {
    content: (string-ascii 1000),
    amended-by: principal,
    amendment-id: uint,
    created-at: uint,
    change-summary: (string-ascii 200)
  })

;; Current NDA version tracker
(define-map nda-current-version uint uint)

;; Amendment history per NDA
(define-map nda-amendment-history uint (list 20 uint))

;; Propose an amendment to an existing NDA
(define-public (propose-amendment
  (nda-id uint)
  (amendment-type uint)
  (new-content (optional (string-ascii 1000)))
  (new-expiration (optional uint))
  (additional-terms (optional (string-ascii 500)))
  (new-signers (optional (list 10 principal)))
  (description (string-ascii 200)))
  (let ((amendment-id (+ (var-get amendment-id-nonce) u1))
        (nda-data (unwrap! (contract-call? .Smart-NDAs get-nda nda-id) err-nda-not-found))
        (voting-deadline (+ (unwrap-panic (get-stacks-block-info? time u0)) (var-get default-voting-period)))
        (amendment-history (default-to (list) (map-get? nda-amendment-history nda-id))))
    (asserts! (is-some nda-data) err-nda-not-found)
    (asserts! (contract-call? .Smart-NDAs has-signed nda-id tx-sender) err-not-authorized)
    (asserts! (and (>= amendment-type amendment-type-content) (<= amendment-type amendment-type-signers)) err-invalid-amendment-type)
    
    ;; Create amendment proposal
    (map-set amendment-proposals amendment-id
      {
        nda-id: nda-id,
        proposer: tx-sender,
        amendment-type: amendment-type,
        new-content: new-content,
        new-expiration: new-expiration,
        additional-terms: additional-terms,
        new-signers: new-signers,
        description: description,
        proposed-at: (unwrap-panic (get-stacks-block-info? time u0)),
        voting-deadline: voting-deadline,
        votes-for: u0,
        votes-against: u0,
        status: "pending",
        executed-at: none
      })
    
    ;; Update amendment history
    (map-set nda-amendment-history nda-id
      (unwrap! (as-max-len? (append amendment-history amendment-id) u20) err-amendment-not-found))
    
    (var-set amendment-id-nonce amendment-id)
    (ok amendment-id)))

;; Vote on an amendment proposal
(define-public (vote-on-amendment (amendment-id uint) (vote bool) (rationale (optional (string-ascii 200))))
  (let ((amendment (unwrap! (map-get? amendment-proposals amendment-id) err-amendment-not-found))
        (vote-key (tuple (amendment-id amendment-id) (voter tx-sender)))
        (current-time (unwrap-panic (get-stacks-block-info? time u0))))
    (asserts! (contract-call? .Smart-NDAs has-signed (get nda-id amendment) tx-sender) err-not-authorized)
    (asserts! (is-eq (get status amendment) "pending") err-amendment-already-executed)
    (asserts! (< current-time (get voting-deadline amendment)) err-amendment-expired)
    (asserts! (is-none (map-get? amendment-votes vote-key)) err-already-voted)
    
    ;; Record the vote
    (map-set amendment-votes vote-key
      {
        vote: vote,
        voted-at: current-time,
        rationale: rationale
      })
    
    ;; Update vote counts
    (if vote
      (map-set amendment-proposals amendment-id 
        (merge amendment {votes-for: (+ (get votes-for amendment) u1)}))
      (map-set amendment-proposals amendment-id 
        (merge amendment {votes-against: (+ (get votes-against amendment) u1)})))
    
    (ok true)))

;; Execute approved amendment
(define-public (execute-amendment (amendment-id uint))
  (let ((amendment (unwrap! (map-get? amendment-proposals amendment-id) err-amendment-not-found))
        (nda-id (get nda-id amendment))
        (current-time (unwrap-panic (get-stacks-block-info? time u0)))
        (total-votes (+ (get votes-for amendment) (get votes-against amendment)))
        (current-version (default-to u0 (map-get? nda-current-version nda-id))))
    (asserts! (is-eq (get status amendment) "pending") err-amendment-already-executed)
    (asserts! (>= current-time (get voting-deadline amendment)) err-amendment-expired)
    (asserts! (>= total-votes u2) err-insufficient-votes) ;; Minimum 2 votes required
    (asserts! (> (get votes-for amendment) (get votes-against amendment)) err-insufficient-votes)
    
    ;; Create new version entry
    (let ((new-version (+ current-version u1))
          (version-key (tuple (nda-id nda-id) (version new-version))))
      
      ;; Store version with content from amendment
      (map-set nda-versions version-key
        {
          content: (default-to "" (get new-content amendment)),
          amended-by: (get proposer amendment),
          amendment-id: amendment-id,
          created-at: current-time,
          change-summary: (get description amendment)
        })
      
      ;; Update current version
      (map-set nda-current-version nda-id new-version)
      
      ;; Mark amendment as executed
      (map-set amendment-proposals amendment-id
        (merge amendment 
          {
            status: "executed",
            executed-at: (some current-time)
          }))
      
      (ok new-version))))

;; Reject expired amendment
(define-public (reject-expired-amendment (amendment-id uint))
  (let ((amendment (unwrap! (map-get? amendment-proposals amendment-id) err-amendment-not-found))
        (current-time (unwrap-panic (get-stacks-block-info? time u0))))
    (asserts! (is-eq (get status amendment) "pending") err-amendment-already-executed)
    (asserts! (>= current-time (get voting-deadline amendment)) err-amendment-expired)
    
    (map-set amendment-proposals amendment-id (merge amendment {status: "expired"}))
    (ok true)))

;; Read-only functions
(define-read-only (get-amendment (amendment-id uint))
  (map-get? amendment-proposals amendment-id))

(define-read-only (get-amendment-vote (amendment-id uint) (voter principal))
  (map-get? amendment-votes (tuple (amendment-id amendment-id) (voter voter))))

(define-read-only (get-nda-version (nda-id uint) (version uint))
  (map-get? nda-versions (tuple (nda-id nda-id) (version version))))

(define-read-only (get-current-nda-version (nda-id uint))
  (default-to u0 (map-get? nda-current-version nda-id)))

(define-read-only (get-nda-amendment-history (nda-id uint))
  (default-to (list) (map-get? nda-amendment-history nda-id)))

(define-read-only (get-amendment-voting-status (amendment-id uint))
  (match (get-amendment amendment-id)
    amendment 
    (let ((total-votes (+ (get votes-for amendment) (get votes-against amendment)))
          (approval-rate (if (> total-votes u0) 
            (/ (* (get votes-for amendment) u100) total-votes) 
            u0)))
      (ok {
        total-votes: total-votes,
        votes-for: (get votes-for amendment),
        votes-against: (get votes-against amendment),
        approval-rate: approval-rate,
        status: (get status amendment),
        time-remaining: (if (> (get voting-deadline amendment) (unwrap-panic (get-stacks-block-info? time u0)))
          (- (get voting-deadline amendment) (unwrap-panic (get-stacks-block-info? time u0)))
          u0)
      }))
    (err err-amendment-not-found)))

(define-read-only (get-nda-version-count (nda-id uint))
  (get-current-nda-version nda-id))

(define-read-only (get-active-amendments-for-nda (nda-id uint))
  (let ((amendments (get-nda-amendment-history nda-id)))
    (ok {
      amendment-1: (get-active-amendment-if-matches nda-id u1),
      amendment-2: (get-active-amendment-if-matches nda-id u2),
      amendment-3: (get-active-amendment-if-matches nda-id u3)
    })))

;; Helper functions
(define-private (get-active-amendment-if-matches (target-nda-id uint) (check-id uint))
  (match (get-amendment check-id)
    amendment 
    (if (and (is-eq (get nda-id amendment) target-nda-id) (is-eq (get status amendment) "pending"))
      (some amendment)
      none)
    none))

(define-read-only (is-amendment-ready-for-execution (amendment-id uint))
  (match (get-amendment amendment-id)
    amendment
    (let ((current-time (unwrap-panic (get-stacks-block-info? time u0)))
          (total-votes (+ (get votes-for amendment) (get votes-against amendment))))
      (and 
        (is-eq (get status amendment) "pending")
        (>= current-time (get voting-deadline amendment))
        (>= total-votes u2)
        (> (get votes-for amendment) (get votes-against amendment))))
    false))
