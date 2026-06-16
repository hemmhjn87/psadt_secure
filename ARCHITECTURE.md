# High-Level Architecture

This diagram provides a conceptual overview of the HemSpect architecture. It visualizes how the CLI entrypoint coordinates the core scanner engines and how various specialized modules interact to produce enterprise-grade security reports.

```mermaid
graph TD
    classDef cli fill:#0a1628,stroke:#00ff88,stroke-width:2px,color:#fff,font-weight:bold
    classDef core fill:#1c2a42,stroke:#f0a500,stroke-width:2px,color:#fff
    classDef module fill:#162032,stroke:#4895ef,stroke-width:1px,color:#e8edf5
    classDef config fill:#2a9d8f,stroke:#1a472a,stroke-width:1px,color:#fff
    classDef output fill:#422010,stroke:#f4a261,stroke-width:1px,color:#fff

    CLI["hemspect<br/>(Rich CLI UI & Arguments)"]:::cli
    
    subgraph "Core Scanning Engine (src/scanners)"
        Engine["scan_psadt.py<br/>(HemSpectScanner Orchestrator)"]:::core
        SBOM["sbom_generator.py<br/>(Binary Analysis & Authenticode)"]:::module
        Approval["approval_workflow.py<br/>(Workflow Status Tracking)"]:::module
        Report["report_generator.py<br/>(Enterprise HTML Renderer)"]:::module
    end
    
    subgraph "Configuration"
        Rules[("rules.yaml<br/>(Threat Signatures)")]:::config
        Allowlist[("allowlist.yaml<br/>(Exceptions & Exclusions)")]:::config
    end
    
    subgraph "Outputs"
        HTML["report.html<br/>(SPA Dashboard)"]:::output
        JSON["findings.json<br/>(Raw Data)"]:::output
    end

    CLI -->|Initializes & Runs| Engine
    
    Rules -.->|Loads Definitions| Engine
    Allowlist -.->|Filters False Positives| Engine
    
    Engine -->|Delegates Binary Checks| SBOM
    SBOM -->|Returns Entropy/Hashes| Engine
    
    Engine -->|Updates Status| Approval
    
    Engine -->|Passes Cleaned Findings| Report
    
    Report -->|Generates| HTML
    Engine -->|Exports| JSON

```

## Key Components

1. **CLI Orchestrator:** The primary interface for operators and CI/CD pipelines. It parses arguments, initializes the environment, and invokes the core engine.
2. **HemSpectScanner:** The "brain" of the operation. It ingests threat signatures from `rules.yaml`, executes the multi-stage scanning process, and evaluates files against the `allowlist.yaml` definitions.
3. **Report Generator:** Transforms raw JSON telemetry and security findings into an interactive, zero-dependency HTML dashboard for security analysts.
