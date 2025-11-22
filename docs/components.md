# CVE Analysis System - Component Breakdown

## 📦 7 Core Components

### 1. Web UI & REST API
**Tech**: FastAPI + React/Next.js

**Endpoints**:
- `POST /api/v1/analyze` - Submit analysis job
- `GET /api/v1/jobs/{job_id}` - Get job status
- `GET /api/v1/reports/{job_id}` - Get report

**Files**:
```
api/
├── main.py
├── routes/
│   ├── analysis.py
│   ├── jobs.py
│   └── reports.py
└── models/
```

---

### 2. Workflow Engine
**Tech**: Prefect (or Airflow)

**Responsibilities**:
- Job queue management
- Task scheduling and execution
- Retry logic and error handling
- Status tracking

**Files**:
```
workflows/
├── flows/
│   └── cve_analysis_flow.py
├── tasks/
│   ├── vuln_db_tasks.py
│   ├── repo_tasks.py
│   ├── indexer_tasks.py
│   ├── agent_tasks.py
│   └── report_tasks.py
└── config.py
```

---

### 3. Vulnerability DB Service ⭐
**Tech**: Python + requests + LangChain

**Plugin Architecture**:
```python
class VulnerabilityDBPlugin(ABC):
    @abstractmethod
    def get_cve_info(self, cve_id: str) -> CVEInfo:
        pass
    
    @abstractmethod
    def get_affected_packages(self, cve_id: str) -> List[Package]:
        pass
    
    @abstractmethod
    def extract_vulnerable_methods(self, cve_id: str) -> List[Method]:
        pass
```

**Plugins**:
- OSV.dev (primary for Python)
- Vulners SDK
- NVD API

**Files**:
```
vuln_db/
├── base.py
├── plugins/
│   ├── osv_plugin.py
│   ├── vulners_plugin.py
│   └── nvd_plugin.py
├── extractors/
│   ├── method_extractor.py
│   └── commit_parser.py
└── models.py
```

---

### 4. Repository Manager
**Tech**: GitPython

**Responsibilities**:
- Clone GitHub repos
- Branch management
- Caching
- Cleanup

**Files**:
```
repo_manager/
├── cloner.py
├── cache.py
└── config.py
```

**Key Functions**:
```python
def clone_repository(repo_url: str, branch: str = None) -> str:
    """Clone repo to temp dir."""
    
def cleanup_repository(repo_path: str):
    """Remove temp files."""
```

---

### 5. Code Indexer ⭐
**Tech**: Python AST + tree-sitter

**Language Analyzer Interface**:
```python
class LanguageAnalyzer(ABC):
    @abstractmethod
    def detect_dependencies(self, repo_path: str) -> Dict[str, str]:
        """Parse requirements.txt, pyproject.toml, etc."""
        pass
    
    @abstractmethod
    def build_ast_index(self, repo_path: str) -> Dict:
        """Build AST index."""
        pass
    
    @abstractmethod
    def build_call_graph(self, ast_index: Dict) -> Dict:
        """Build method call graph."""
        pass
```

**Analyzers**:
- Python (MVP)
- Java (future)
- JavaScript (future)

**Files**:
```
indexer/
├── base.py
├── analyzers/
│   ├── python_analyzer.py
│   ├── java_analyzer.py
│   └── javascript_analyzer.py
├── parsers/
│   ├── dependency_parser.py
│   └── ast_parser.py
└── models.py
```

---

### 6. AI Agent Service ⭐
**Tech**: LangChain Deep-Agents + Gemini

**Custom Tools**:
```python
@tool
def search_code_tool(method_name: str, code_index: dict) -> dict:
    """Search for method invocations."""
    
@tool
def analyze_dataflow_tool(file_path: str, line: int, code_index: dict) -> dict:
    """Analyze exploitability."""
    
@tool
def suggest_fix_tool(cve_id: str, package: str, version: str) -> dict:
    """Generate fix recommendations."""
```

**Files**:
```
agent_service/
├── agent.py
├── tools/
│   ├── code_search.py
│   ├── dataflow.py
│   ├── fix_generator.py
│   └── report_writer.py
├── prompts/
│   └── system_prompt.py
└── config.py
```

---

### 7. Report Generator
**Tech**: Jinja2 + HTML/JSON

**Report Structure**:
```python
@dataclass
class VulnerabilityReport:
    job_id: str
    cve_id: str
    status: str  # VULNERABLE, NOT_VULNERABLE, UNKNOWN
    findings: List[Finding]
    recommendations: List[str]

@dataclass
class Finding:
    file_path: str
    line_number: int
    method_name: str
    exploitable: bool
    confidence: float
    explanation: str
    suggested_fix: str
```

**Files**:
```
report_generator/
├── generators/
│   ├── html_generator.py
│   ├── json_generator.py
│   └── pdf_generator.py
└── templates/
    └── report.html.j2
```

---

## 🔗 Component Dependencies

```
API → Workflow Engine → All Services
                      ↓
Vuln DB ← AI Agent → Code Indexer ← Repo Manager
                ↓
           Report Generator
```

---

## 🎯 Development Timeline

### Phase 1: Core Components (Week 1-2)
- [ ] Vuln DB Service (OSV.dev only)
- [ ] Repo Manager
- [ ] Code Indexer (Python only)
- [ ] Unit tests

### Phase 2: Intelligence (Week 2-3)
- [ ] AI Agent Service
- [ ] Report Generator (HTML)
- [ ] Integration tests

### Phase 3: Orchestration (Week 3-4)
- [ ] Workflow Engine (Prefect)
- [ ] REST API
- [ ] E2E tests

### Phase 4: UI & Polish (Week 4-5)
- [ ] Web Frontend
- [ ] Additional reports (JSON, PDF)
- [ ] Performance optimization

### Phase 5: Extensibility (Week 5-6)
- [ ] Additional vuln DB plugins
- [ ] Additional language analyzers
- [ ] CI/CD integration

---

## 🧪 Testing Strategy

### Unit Tests (Per Component)
```
tests/
├── test_vuln_db/
├── test_repo_manager/
├── test_indexer/
├── test_agent/
└── test_report_generator/
```

### Integration Tests
Test component interactions with mock data

### E2E Tests
Test with known CVEs:
- CVE-2022-40897 (setuptools)
- CVE-2021-44228 (log4j)

---

## 📊 Component Interfaces

| Component | Input | Output |
|-----------|-------|--------|
| Vuln DB Service | `cve_id: str` | `CVEInfo` |
| Repo Manager | `repo_url: str` | `repo_path: str` |
| Code Indexer | `repo_path: str` | `CodeIndex` |
| AI Agent | `CVEInfo, CodeIndex` | `Analysis` |
| Report Generator | `Analysis` | HTML/JSON |

---

## 🚀 Quick Start Commands

### Test Vuln DB Service
```bash
pip install requests langchain
python -c "from vuln_db.plugins.osv_plugin import OSVPlugin; \
           print(OSVPlugin().get_cve_info('CVE-2022-40897'))"
```

### Test Code Indexer
```bash
pip install tree-sitter toml pyyaml
python -c "from indexer.analyzers.python_analyzer import PythonAnalyzer; \
           idx = PythonAnalyzer().build_index('/path/to/repo')"
```

### Test AI Agent
```bash
pip install langchain deepagents langchain-google-genai
python -c "from agent_service.agent import create_vulnerability_agent; \
           agent = create_vulnerability_agent()"
```
