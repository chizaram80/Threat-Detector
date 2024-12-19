# Anti-Phishing Smart Contract

A blockchain-based solution for detecting, reporting, and managing phishing threats in web environments. This smart contract implements a decentralized system for website verification, threat reporting, and security monitoring.

## About

The Anti-Phishing Smart Contract provides a comprehensive framework for:
- Website verification and security certification
- Threat detection and reporting
- Security monitoring and assessment
- Risk management and threat mitigation

## Core Features

### 1. Website Registration and Verification
- Secure registration of websites with verification mechanisms
- Security certificate management
- Collateral-based security backing
- Automated risk scoring system

### 2. Threat Reporting System
- Decentralized threat reporting mechanism
- Evidence documentation and verification
- Threat severity assessment
- Multi-stage verification process

### 3. Security Monitoring
- Dedicated security monitors with staked collateral
- Performance tracking and reliability scoring
- Automated activity monitoring
- Reward mechanisms for accurate reporting

## Technical Specifications

### System Constants
- Minimum Idle Period: 24 hours (86400 seconds)
- Minimum Security Deposit: 1,000,000 microSTX
- Minimum Trust Score: 50
- Maximum Evidence Length: 500 characters

### Smart Contract Functions

#### Website Management
```clarity
register-secure-website (website_identifier, security_certificate)
get-website-status (website_identifier)
check-website-threats (website_identifier)
```

#### Threat Reporting
```clarity
submit-threat-report (website_identifier, evidence_documentation, threat_severity)
verify-threat-report (website_identifier, is_verified)
```

#### Security Monitoring
```clarity
register-security-monitor (collateral_amount)
get-monitor-rating (monitor_id)
```

#### System Administration
```clarity
update-security-level (new_security_level)
set-emergency-pause (pause_status)
transfer-contract-control (new_administrator)
initialize-contract (administrator)
```

## Security Features

### Input Validation
- Website identifier validation
- Security certificate verification
- Threat evidence documentation checks
- Threat severity assessment

### Risk Management
- Collateral-based security
- Graduated risk scoring
- Activity monitoring
- Emergency pause mechanism

### Access Control
- Administrator-only functions
- Monitor verification system
- Time-based restrictions
- Minimum collateral requirements

## Error Codes

| Code | Description |
|------|-------------|
| u100 | Access Forbidden |
| u101 | Duplicate Entry Error |
| u102 | Entry Missing Error |
| u103 | Operation Blocked Error |
| u104 | Collateral Missing Error |
| u105 | Time Restriction Error |
| u106 | Limit Breach Error |
| u400-405 | Various Validation Errors |

## Usage

### 1. Website Registration
To register a website:
```clarity
(contract-call? 
    .anti-phishing-contract 
    register-secure-website 
    "website-identifier" 
    "security-certificate")
```

### 2. Submitting Threat Reports
To submit a threat report:
```clarity
(contract-call? 
    .anti-phishing-contract 
    submit-threat-report 
    "website-identifier" 
    "evidence-documentation" 
    threat-severity)
```

### 3. Becoming a Security Monitor
To register as a security monitor:
```clarity
(contract-call? 
    .anti-phishing-contract 
    register-security-monitor 
    collateral-amount)
```

## System Requirements

### Minimum Collateral
- Website Registration: Variable based on security intensity level
- Security Monitor Registration: 1,000,000 microSTX

### Time Restrictions
- Minimum period between reports: 24 hours
- Security checks: Based on risk level

## Best Practices

1. Website Registration
   - Provide comprehensive security certificates
   - Maintain adequate collateral
   - Regular security updates

2. Threat Reporting
   - Include detailed evidence documentation
   - Accurate threat severity assessment
   - Timely reporting

3. Security Monitoring
   - Maintain high reliability scores
   - Regular activity participation
   - Accurate threat verification

## Emergency Procedures

1. Emergency Pause
   - Contract administrator can pause system
   - Affects all new operations
   - Existing data remains secure

2. Risk Management
   - Automated risk score adjustments
   - Threat verification system
   - Collateral protection mechanisms

## Contributing

When contributing to this contract:
1. Follow the existing code structure
2. Maintain comprehensive input validation
3. Include appropriate error handling
4. Add thorough documentation