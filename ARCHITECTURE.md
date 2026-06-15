# HemSpect Project Architecture

This interactive diagram provides a high-level conceptual overview of the `psadt-secure` project's architecture. It visualizes how the CLI entrypoint connects to the core scanner engine, and how the various specialized modules interact to produce the final enterprise HTML reports. 

You can use this directly in your team presentation to explain the tool's workflow!

```mermaid
graph TD
    %% Styling
    classDef cli fill:#0a1628,stroke:#00ff88,stroke-width:2px,color:#fff,font-weight:bold
    classDef core fill:#1c2a42,stroke:#f0a500,stroke-width:2px,color:#fff
    classDef module fill:#162032,stroke:#4895ef,stroke-width:1px,color:#e8edf5
    classDef config fill:#2a9d8f,stroke:#1a472a,stroke-width:1px,color:#fff
    classDef output fill:#422010,stroke:#f4a261,stroke-width:1px,color:#fff

    %% Nodes
    CLI["main.py<br/>(Rich CLI UI & Arguments)"]:::cli
    
    subgraph "Core Scanning Engine (src/scanners)"
        Engine["scan_psadt.py<br/>(HemSpectScanner Orchestrator)"]:::core
        SBOM["sbom_generator.py<br/>(Binary Analysis & Authenticode)"]:::module
        Approval["approval_workflow.py<br/>(Workflow Status Tracking)"]:::module
        Report["report_generator.py<br/>(Enterprise HTML Renderer)"]:::module
    end
    
    subgraph "Configuration (config/)"
        Rules[("rules.yaml<br/>(Threat Signatures)")]:::config
        Allowlist[("allowlist.yaml<br/>(Exceptions & Exclusions)")]:::config
    end
    
    subgraph "Outputs"
        HTML["report.html<br/>(SPA Dashboard)"]:::output
        JSON["findings.json<br/>(Raw Data)"]:::output
    end

    %% Dependencies & Data Flow
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

> [!TIP]
> **Presentation Tip:** You can hover over this diagram and use the zoom/pan tools in the bottom corner. In your presentation, you can explain that `scan_psadt.py` is the "brain" of the operation, pulling threat rules from `rules.yaml`, running the 8-step scan, and then tossing the results over to `report_generator.py` to build the beautiful UI.
