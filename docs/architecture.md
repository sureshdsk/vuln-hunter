# CVE Vulnerability Analysis System - Architecture Document

## 🎯 Project Overview

AI-powered vulnerability analysis system that automatically:
1. Analyzes public GitHub repositories for specific CVE vulnerabilities
2. Detects vulnerable methods/functions in Python codebases (extensible to other languages)
3. Provides detailed reports with code references and optional fixes
4. Scales via workflow orchestration (Airflow/Prefect)

---

## 🔄 User Workflow

### Input
- GitHub repository URL
- Branch name (optional, defaults to main)
- CVE ID

### Process
1. User enters public GitHub repo and optional branch and CVE ID
2. Analysis workflow starts
3. Get information related to CVE ID from OSV.dev or any other vuln DB
4. System downloads source code
5. Build source code index or embedding for finding issues
6. AI Agent runs analysis on source code
7. Provides report with references and optional fix

### Output
- Analysis report (HTML/JSON/PDF)
- Vulnerable method locations with line numbers
- Exploitability assessment
- Fix recommendations

---

## 🏗️ System Architecture

### High-Level Components

```
┌─────────────┐
│   Web UI    │
│   REST API  │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Workflow Engine │ (Prefect/Airflow)
└─────────┬───────┘
          │
    ┌─────┴─────┬─────────┬──────────┬──────────┐
    ▼           ▼         ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│Vuln DB │ │  Repo  │ │  Code  │ │   AI   │ │Report  │
│Service │ │Manager │ │Indexer │ │ Agent  │ │  Gen   │
└────────┘ └────────┘ └────────┘ └────────┘ └────────┘
```

---

## 💻 Tech Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Orchestration** | Prefect or Airflow | Scalable workflow management |
| **AI Agent** | LangChain Deep-Agents | Complex multi-step tasks, sub-agents, memory |
| **LLM** | Gemini 2.0 Flash or GPT-4 | Fast, accurate code analysis |
| **Vuln DB** | OSV.dev (primary) + Vulners | Best Python support, extensible |
| **Language Analysis** | Python AST + tree-sitter | Native Python, extensible |
| **API** | FastAPI | Async support, auto docs |
| **Code Indexing** | AST + Vector embeddings | Fast search, semantic understanding |
| **Report Generation** | Jinja2 + HTML/JSON | Flexible templating |
| **Graph Workflow** | LangGraph | Native to LangChain |

---

## 🔌 Extensibility Design

### Multi-Source Vulnerability Database
Plugin architecture supports multiple CVE data sources:
- **OSV.dev** - Primary for Python/PyPI
- **Vulners** - Commercial, curated data
- **NVD** - NIST National Vulnerability Database

```python
# Adding new source
class CustomVulnDB(VulnerabilityDBPlugin):
    def get_cve_info(self, cve_id: str) -> CVEInfo:
        # Custom implementation
        pass
```

### Multi-Language Support
Analyzer plugins for different programming languages:
- **Python** - MVP implementation
- **Java** - Future
- **JavaScript** - Future
- **Go/Rust** - Future

```python
# Adding new language
class RustAnalyzer(LanguageAnalyzer):
    dependency_files = ['Cargo.toml', 'Cargo.lock']
    
    def build_index(self, repo_path: str) -> CodeIndex:
        # Implement Rust-specific parsing
        pass
```

---

## 🤖 Deep-Agents Integration

### Why Deep-Agents?

**Key Advantages**:
1. **Task Decomposition** - Automatically breaks CVE analysis into subtasks
2. **Context Management** - Handles large repositories without token limits
3. **Sub-Agent Pattern** - Delegates to specialized agents
4. **Persistent Memory** - Learns from previous analyses
5. **Human-in-the-Loop** - Can request approval for fixes

### Agent Workflow
```python
from deepagents import create_deep_agent
from langchain_google_genai import ChatGoogleGenerativeAI

agent = create_deep_agent(
    llm=ChatGoogleGenerativeAI(model="gemini-2.0-flash-exp"),
    tools=[
        search_code_tool,
        analyze_dataflow_tool,
        suggest_fix_tool,
        write_analysis_report
    ],
    system_prompt="Security vulnerability analyst..."
)
```

### Custom Tools
- **search_code_tool** - Find method invocations in code
- **analyze_dataflow_tool** - Assess exploitability
- **suggest_fix_tool** - Generate remediation advice
- **write_analysis_report** - Create structured findings

---

## 📊 Workflow Orchestration

### Prefect Example
```python
from prefect import flow, task

@task
def fetch_cve_data(cve_id: str) -> CVEInfo:
    plugin = OSVPlugin()
    return plugin.get_cve_info(cve_id)

@task
def clone_repository(repo_url: str) -> str:
    return git.clone(repo_url)

@task
def build_code_index(repo_path: str) -> CodeIndex:
    analyzer = PythonAnalyzer()
    return analyzer.build_index(repo_path)

@task
def run_ai_agent(cve_info: CVEInfo, code_index: CodeIndex) -> Analysis:
    agent = VulnerabilityAnalysisAgent()
    return agent.analyze(cve_info, code_index)

@flow
def analyze_vulnerability(repo_url: str, cve_id: str):
    cve_data = fetch_cve_data(cve_id)
    repo_path = clone_repository(repo_url)
    code_index = build_code_index(repo_path)
    analysis = run_ai_agent(cve_data, code_index)
    report = generate_report(analysis)
    return report
```

---

## 📈 Success Metrics

- **Accuracy**: >85% precision in vulnerable method detection
- **Speed**: <2 minutes for typical Python repo (<10K LOC)
- **Coverage**: Support 90% of Python CVEs with method-level info
- **Scalability**: Handle 100+ concurrent analysis jobs

---

## 🚀 Development Phases

### Phase 1: Core Pipeline (2-3 weeks)
- OSV.dev integration
- GitHub repo cloning
- Python dependency parsing
- Basic method search
- Google ADK/Deep-agents setup
- Simple report generation
- Prefect workflow
- Web API (FastAPI)

### Phase 2: Extensibility (1-2 weeks)
- Multiple vuln DB support (Vulners, NVD)
- Plugin architecture
- Configuration management
- Enhanced reporting (HTML, JSON, PDF)

### Phase 3: Advanced Features (2-3 weeks)
- Multi-language support (Java, JavaScript)
- AI-powered fix generation
- CI/CD integration (GitHub Actions)
- Caching and performance optimization

---

## 📁 Project Structure

```
cve-analyzer/
├── README.md
├── requirements.txt
├── docker-compose.yml
│
├── api/                    # REST API
├── workflows/              # Prefect/Airflow
├── vuln_db/                # Vulnerability DB plugins
├── repo_manager/           # Git operations
├── indexer/                # Code indexing
├── agent_service/          # Deep-agents AI
├── report_generator/       # Report generation
├── web/                    # Frontend UI
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
└── config/
    ├── prefect_config.yaml
    └── agent_config.yaml
```

---

## 🎯 Next Steps

1. **Prototype OSV.dev integration** - Test CVE data extraction
2. **Build Python code indexer** - AST parsing and method call detection
3. **Set up deep-agents** - Configure LangChain agent with custom tools
4. **Create Prefect workflow** - End-to-end pipeline
5. **Test on known vulnerabilities** - Validate with CVE-2022-40897 (setuptools)
