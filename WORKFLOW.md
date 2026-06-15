# HemSpect Process Flow (Business View)

This flowchart is designed for non-technical stakeholders (management, auditors, project managers). It strips away the technical code structure and focuses entirely on the **business value** and **decision-making workflow** of the scanner.

You can use this in presentations to explain *why* the tool exists and *what* it does for the organization!

```mermaid
graph TD
    %% Styling for a non-tech audience
    classDef input fill:#e8edf5,stroke:#8ba0be,stroke-width:2px,color:#0a1628,font-weight:bold
    classDef action fill:#2a9d8f,stroke:#1a472a,stroke-width:2px,color:#fff,font-weight:bold
    classDef decision fill:#f4a261,stroke:#422010,stroke-width:2px,color:#000,font-weight:bold
    classDef pass fill:#1a472a,stroke:#6ee7b7,stroke-width:2px,color:#fff,font-weight:bold
    classDef fail fill:#e63946,stroke:#3b0a0a,stroke-width:2px,color:#fff,font-weight:bold

    %% Flow Steps
    Start([1. New Software Package Submitted]):::input
    Scan[2. Automated Security Scan<br/>Checks for passwords, malware, & data leaks]:::action
    Policy[3. Policy & Exceptions Check<br/>Ignores known safe files]:::action
    Decide{4. Is the Package Safe?}:::decision
    
    Pass([Approved for Deployment]):::pass
    Fail([Rejected / Review Required]):::fail
    Report[5. Generate Dashboard Report<br/>For Auditing & Tracking]:::input

    %% Connections
    Start --> Scan
    Scan --> Policy
    Policy --> Decide
    
    Decide -->|No Critical Risks| Pass
    Decide -->|High/Critical Risks Found| Fail
    
    Pass --> Report
    Fail --> Report
```

> [!TIP]
> **Talking Points for this Chart:**
> 1. **Automation:** Emphasize that Step 2 saves countless hours of manual code review.
> 2. **Smart Filtering:** Highlight Step 3 (Policy & Exceptions) as the feature that prevents "alert fatigue" by ignoring known false positives.
> 3. **Clear Decisions:** Explain that the tool gives a definitive Yes/No answer (Step 4), enforcing strict deployment security standards.
