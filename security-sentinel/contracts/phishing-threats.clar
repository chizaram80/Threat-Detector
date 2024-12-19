;; Anti-Phishing Smart Contract

;; Error codes
(define-constant ACCESS_FORBIDDEN (err u100))
(define-constant DUPLICATE_ENTRY_ERROR (err u101))
(define-constant ENTRY_MISSING_ERROR (err u102))
(define-constant OPERATION_BLOCKED_ERROR (err u103))
(define-constant COLLATERAL_MISSING_ERROR (err u104))
(define-constant TIME_RESTRICTION_ERROR (err u105))
(define-constant LIMIT_BREACH_ERROR (err u106))
(define-constant TEMPORAL_ERROR (err u107))
(define-constant INVALID_WEB_IDENTIFIER (err u400))
(define-constant INVALID_SECURITY_ENDORSEMENT (err u401))
(define-constant INVALID_PROOF_DOCUMENTATION (err u402))
(define-constant INVALID_THREAT_MAGNITUDE (err u403))
(define-constant INVALID_PROTECTION_LEVEL (err u404))
(define-constant INVALID_CONTROLLER_ADDRESS (err u405))

;; System constants
(define-constant MINIMUM_IDLE_PERIOD u86400) ;; 24 hours in seconds
(define-constant MINIMUM_SECURITY_DEPOSIT u1000000) ;; in microSTX
(define-constant MINIMUM_TRUST_SCORE u50)
(define-constant MAXIMUM_EVIDENCE_LENGTH u500)

;; Input validation functions
(define-private (validate-website-identifier (website_identifier (string-ascii 255)))
    (begin
        (asserts! (>= (len website_identifier) u3) (err "Website ID too short"))
        (asserts! (<= (len website_identifier) u255) (err "Website ID too long"))
        (asserts! (is-eq (index-of website_identifier ".") none) (err "Invalid character: ."))
        (asserts! (is-eq (index-of website_identifier "/") none) (err "Invalid character: /"))
        (asserts! (is-eq (index-of website_identifier " ") none) (err "Invalid character: space"))
        (ok true)))

(define-private (validate-security-certificate (security_certificate (string-ascii 50)))
    (begin
        (asserts! (>= (len security_certificate) u5) (err "Certificate too short"))
        (asserts! (<= (len security_certificate) u50) (err "Certificate too long"))
        (asserts! (is-eq (index-of security_certificate "<") none) (err "Invalid character: <"))
        (asserts! (is-eq (index-of security_certificate ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-threat-evidence (evidence_documentation (string-ascii 500)))
    (begin
        (asserts! (>= (len evidence_documentation) u10) (err "Evidence documentation too short"))
        (asserts! (<= (len evidence_documentation) u500) (err "Evidence documentation too long"))
        (asserts! (is-eq (index-of evidence_documentation "<") none) (err "Invalid character: <"))
        (asserts! (is-eq (index-of evidence_documentation ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-threat-severity (threat_severity uint))
    (begin
        (asserts! (>= threat_severity u1) (err "Threat severity too low"))
        (asserts! (<= threat_severity u100) (err "Threat severity too high"))
        (ok true)))

(define-private (validate-security-level (security_level uint))
    (begin
        (asserts! (>= security_level u1) (err "Security level too low"))
        (asserts! (<= security_level u10) (err "Security level too high"))
        (ok true)))

;; Administrative state variables
(define-data-var contract_administrator principal tx-sender)
(define-data-var registration_fee uint u100)
(define-data-var minimum_alert_confirmations uint u5)
(define-data-var security_intensity_level uint u1)
(define-data-var contract_emergency_pause bool false)

;; Primary data structures
(define-map verified_websites
    {website_identifier: (string-ascii 255)}
    {
        website_owner: principal,
        security_level: (string-ascii 20),
        registration_timestamp: uint,
        risk_score: uint,
        reported_incidents: uint,
        staked_collateral: uint,
        last_security_check: uint,
        security_certificate: (string-ascii 50)
    })

(define-map reported_malicious_sites
    {website_identifier: (string-ascii 255)}
    {
        reporting_entity: principal,
        report_timestamp: uint,
        evidence_documentation: (string-ascii 500),
        verification_status: (string-ascii 20),
        threat_severity: uint,
        affected_users: uint
    })

(define-map security_monitor_performance
    {monitor_id: principal, monitored_site: (string-ascii 255)}
    {
        total_reports: uint,
        last_report_timestamp: uint,
        reliability_score: uint,
        staked_amount: uint,
        confirmed_reports: uint
    })

(define-map website_security_audits
    {website_identifier: (string-ascii 255)}
    {
        audit_frequency: uint,
        last_audit_timestamp: uint,
        auditor_identity: principal,
        security_score: uint,
        compliance_level: (string-ascii 50)
    })

(define-map security_monitor_registry
    {monitor_id: principal}
    {
        staked_collateral: uint,
        total_assessments: uint,
        accuracy_score: uint,
        last_activity_timestamp: uint,
        monitor_status: (string-ascii 20)
    })

;; Query functions
(define-read-only (get-website-status (website_identifier (string-ascii 255)))
    (match (map-get? verified_websites {website_identifier: website_identifier})
        website_entry (ok website_entry)
        (err ENTRY_MISSING_ERROR)))

(define-read-only (check-website-threats (website_identifier (string-ascii 255)))
    (is-some (map-get? reported_malicious_sites {website_identifier: website_identifier})))

(define-read-only (get-monitor-rating (monitor_id principal))
    (match (map-get? security_monitor_performance {monitor_id: monitor_id, monitored_site: ""})
        monitor_data (get reliability_score monitor_data)
        u0))

;; Core operations
(define-public (register-secure-website 
    (website_identifier (string-ascii 255))
    (security_certificate (string-ascii 50)))
    (let (
        (current_timestamp (unwrap-panic (get-block-info? time (- block-height u1))))
        (required_collateral (* MINIMUM_SECURITY_DEPOSIT (var-get security_intensity_level))))
        
        ;; Input validation
        (asserts! (is-ok (validate-website-identifier website_identifier)) INVALID_WEB_IDENTIFIER)
        (asserts! (is-ok (validate-security-certificate security_certificate)) INVALID_SECURITY_ENDORSEMENT)
        (asserts! (is-eq tx-sender (var-get contract_administrator)) ACCESS_FORBIDDEN)
        (asserts! (>= (stx-get-balance tx-sender) required_collateral) COLLATERAL_MISSING_ERROR)
        
        (match (map-get? verified_websites {website_identifier: website_identifier})
            existing_site DUPLICATE_ENTRY_ERROR
            (begin
                (try! (stx-transfer? required_collateral tx-sender (as-contract tx-sender)))
                (map-set verified_websites
                    {website_identifier: website_identifier}
                    {
                        website_owner: tx-sender,
                        security_level: "verified",
                        registration_timestamp: current_timestamp,
                        risk_score: u0,
                        reported_incidents: u0,
                        staked_collateral: required_collateral,
                        last_security_check: current_timestamp,
                        security_certificate: security_certificate
                    })
                (ok true)))))

(define-public (submit-threat-report 
    (website_identifier (string-ascii 255)) 
    (evidence_documentation (string-ascii 500))
    (threat_severity uint))
    (let (
        (current_timestamp (unwrap-panic (get-block-info? time (- block-height u1))))
        (monitor_data (default-to 
            {total_reports: u0, last_report_timestamp: u0, reliability_score: u0, staked_amount: u0, confirmed_reports: u0}
            (map-get? security_monitor_performance {monitor_id: tx-sender, monitored_site: website_identifier}))))
        
        ;; Input validation
        (asserts! (is-ok (validate-website-identifier website_identifier)) INVALID_WEB_IDENTIFIER)
        (asserts! (is-ok (validate-threat-evidence evidence_documentation)) INVALID_PROOF_DOCUMENTATION)
        (asserts! (is-ok (validate-threat-severity threat_severity)) INVALID_THREAT_MAGNITUDE)
        (asserts! (not (var-get contract_emergency_pause)) OPERATION_BLOCKED_ERROR)
        (asserts! (>= (get reliability_score monitor_data) MINIMUM_TRUST_SCORE) COLLATERAL_MISSING_ERROR)
        (asserts! (> (- current_timestamp (get last_report_timestamp monitor_data)) MINIMUM_IDLE_PERIOD) TIME_RESTRICTION_ERROR)
        
        (map-set reported_malicious_sites
            {website_identifier: website_identifier}
            {
                reporting_entity: tx-sender,
                report_timestamp: current_timestamp,
                evidence_documentation: evidence_documentation,
                verification_status: "pending",
                threat_severity: threat_severity,
                affected_users: u1
            })
        
        (map-set security_monitor_performance
            {monitor_id: tx-sender, monitored_site: website_identifier}
            {
                total_reports: (+ (get total_reports monitor_data) u1),
                last_report_timestamp: current_timestamp,
                reliability_score: (+ (get reliability_score monitor_data) u5),
                staked_amount: (get staked_amount monitor_data),
                confirmed_reports: (get confirmed_reports monitor_data)
            })
        (ok true)))

(define-private (update-website-risk (website_identifier (string-ascii 255)) (risk_adjustment int))
    (begin 
        (asserts! (is-ok (validate-website-identifier website_identifier)) INVALID_WEB_IDENTIFIER)
        (match (map-get? verified_websites {website_identifier: website_identifier})
            website_entry 
                (begin
                    (map-set verified_websites
                        {website_identifier: website_identifier}
                        (merge website_entry {
                            risk_score: (+ (get risk_score website_entry) 
                                (if (> risk_adjustment 0) 
                                    (to-uint risk_adjustment)
                                    u0))
                        }))
                    (ok true))
            ENTRY_MISSING_ERROR)))

(define-public (verify-threat-report 
    (website_identifier (string-ascii 255))
    (is_verified bool))
    (let (
        (current_timestamp (unwrap-panic (get-block-info? time (- block-height u1))))
        (monitor_status (unwrap! (map-get? security_monitor_registry {monitor_id: tx-sender}) ACCESS_FORBIDDEN)))
        
        (asserts! (is-ok (validate-website-identifier website_identifier)) INVALID_WEB_IDENTIFIER)
        (asserts! (>= (get staked_collateral monitor_status) MINIMUM_SECURITY_DEPOSIT) COLLATERAL_MISSING_ERROR)
        
        (map-set security_monitor_registry
            {monitor_id: tx-sender}
            (merge monitor_status {
                total_assessments: (+ (get total_assessments monitor_status) u1),
                last_activity_timestamp: current_timestamp
            }))
        (if is_verified
            (update-website-risk website_identifier 10)
            (update-website-risk website_identifier -5))))

(define-public (register-security-monitor (collateral_amount uint))
    (let (
        (current_timestamp (unwrap-panic (get-block-info? time (- block-height u1)))))
        (asserts! (>= collateral_amount MINIMUM_SECURITY_DEPOSIT) COLLATERAL_MISSING_ERROR)
        (asserts! (>= (stx-get-balance tx-sender) collateral_amount) COLLATERAL_MISSING_ERROR)
        
        (map-set security_monitor_registry
            {monitor_id: tx-sender}
            {
                staked_collateral: collateral_amount,
                total_assessments: u0,
                accuracy_score: u100,
                last_activity_timestamp: current_timestamp,
                monitor_status: "active"
            })
        (unwrap! (stx-transfer? collateral_amount tx-sender (as-contract tx-sender))
                 COLLATERAL_MISSING_ERROR)
        (ok true)))

;; System management functions
(define-public (update-security-level (new_security_level uint))
    (begin
        (asserts! (is-ok (validate-security-level new_security_level)) INVALID_PROTECTION_LEVEL)
        (asserts! (is-eq tx-sender (var-get contract_administrator)) ACCESS_FORBIDDEN)
        (var-set security_intensity_level new_security_level)
        (ok true)))

(define-public (set-emergency-pause (pause_status bool))
    (begin
        (asserts! (is-eq tx-sender (var-get contract_administrator)) ACCESS_FORBIDDEN)
        (var-set contract_emergency_pause pause_status)
        (ok true)))

(define-public (transfer-contract-control (new_administrator principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract_administrator)) ACCESS_FORBIDDEN)
        (asserts! (not (is-eq new_administrator 'SP000000000000000000002Q6VF78)) INVALID_CONTROLLER_ADDRESS)
        (var-set contract_administrator new_administrator)
        (ok true)))

;; System initialization
(define-public (initialize-contract (administrator principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract_administrator)) ACCESS_FORBIDDEN)
        (asserts! (not (is-eq administrator 'SP000000000000000000002Q6VF78)) INVALID_CONTROLLER_ADDRESS)
        (var-set contract_administrator administrator)
        (var-set security_intensity_level u1)
        (var-set contract_emergency_pause false)
        (ok true)))