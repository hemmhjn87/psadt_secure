# Process Workflow

This flowchart outlines the automated decision-making process within HemSpect. It details the journey of a software package from submission to final approval, illustrating how security policies are enforced at each stage.

## Package Security Lifecycle

```mermaid
graph TD
    classDef input fill:#e8edf5,stroke:#8ba0be,stroke-width:2px,color:#0a1628,font-weight:bold
    classDef action fill:#2a9d8f,stroke:#1a472a,stroke-width:2px,color:#fff,font-weight:bold
    classDef decision fill:#f4a261,stroke:#422010,stroke-width:2px,color:#000,font-weight:bold
    classDef pass fill:#1a472a,stroke:#6ee7b7,stroke-width:2px,color:#fff,font-weight:bold
    classDef fail fill:#e63946,stroke:#3b0a0a,stroke-width:2px,color:#fff,font-weight:bold

    Start([1. New Software Package Submitted]):::input
    Scan[2. Automated Security Scan<br/>Checks for passwords, malware, & data leaks]:::action
    Policy[3. Policy & Exceptions Check<br/>Ignores known safe files]:::action
    Decide{4. Is the Package Safe?}:::decision
    
    Pass([Approved for Deployment]):::pass
    Fail([Rejected / Review Required]):::fail
    Report[5. Generate Dashboard Report<br/>For Auditing & Tracking]:::input

    Start --> Scan
    Scan --> Policy
    Policy --> Decide
    
    Decide -->|No Critical Risks| Pass
    Decide -->|High/Critical Risks Found| Fail
    
    Pass --> Report
    Fail --> Report
```

## Workflow Phases

1. **Automated Analysis:** HemSpect performs a deep, multi-engine scan without requiring human intervention, identifying structural flaws, malware signatures, and hardcoded secrets.
2. **Policy Adherence:** Utilizing the configurable `allowlist.yaml`, the engine intelligently filters out known false positives to prevent alert fatigue.
3. **Decisive Action:** Packages failing to meet organizational security thresholds are automatically blocked, generating alerts for the security team, while safe packages are cleared for deployment.
