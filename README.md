# CVE Vulnerability Hunter - Monorepo

AI-powered vulnerability analysis system that automatically analyzes public GitHub repositories for specific CVE vulnerabilities.

## 🏗️ Monorepo Structure

```
vuln-hunter/
├── backend/          # Django REST API
├── frontend/         # React web application
├── workflows/        # Prefect workflow orchestration
├── shared/           # Shared Python models and utilities
├── docs/             # Documentation
└── docker-compose.yml
```

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- PostgreSQL 15+
- Docker & Docker Compose (optional)
- [uv](https://github.com/astral-sh/uv) - Python package manager

### Using Docker Compose (Recommended)

```bash
# Start all services
docker-compose up -d

# Access the services:
# - Frontend: http://localhost:3000
# - Backend API: http://localhost:8000
# - Prefect UI: http://localhost:4200
```

### Local Development

#### Backend Setup

```bash
cd backend

# Install dependencies with uv
uv sync

# Run migrations
uv run python manage.py migrate

# Create superuser
uv run python manage.py createsuperuser

# Start development server
uv run python manage.py runserver
```

#### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

#### Workflows Setup

```bash
cd workflows

# Install dependencies with uv
uv sync

# Start Prefect server (in a separate terminal)
uv run prefect server start

# Deploy workflows
uv run prefect deploy --all

# Start worker
uv run prefect worker start --pool default-pool
```

## 📦 Components

### Backend (Django)

- **Jobs App** - Manages CVE analysis jobs
- **Reports App** - Stores and serves vulnerability reports
- **Vulnerabilities App** - CVE information from databases

**API Endpoints:**
- `POST /api/v1/jobs/create/` - Submit new analysis job
- `GET /api/v1/jobs/` - List all jobs
- `GET /api/v1/jobs/{job_id}/` - Get job details
- `GET /api/v1/reports/{job_id}/` - Get vulnerability report
- `GET /api/v1/vulnerabilities/{cve_id}/` - Get CVE information

### Frontend (React + Vite)

- Analysis submission form
- Job status dashboard
- Report viewer with findings
- CVE information display

### Workflows (Prefect)

Main CVE Analysis Flow:
1. Fetch CVE data from vulnerability databases (OSV.dev, NVD, Vulners)
2. Clone GitHub repository
3. Build code index (AST + dependency analysis)
4. Run AI agent analysis (LangChain + Gemini)
5. Generate vulnerability report
6. Cleanup temporary files

### Shared Package

- Pydantic models for type safety across services
- Shared configuration
- Common utilities

## 🛠️ Technology Stack

| Component | Technology |
|-----------|-----------|
| Backend API | Django + Django REST Framework |
| Frontend | React + Vite |
| Workflow Engine | Prefect 3.x |
| AI/LLM | LangChain + Google Gemini 2.0 |
| Database | PostgreSQL |
| Vulnerability DBs | OSV.dev, NVD, Vulners |
| Code Analysis | Python AST + tree-sitter |
| Package Manager | uv (Python), npm (JavaScript) |

## 🧪 Development Workflow

### Running Tests

```bash
# Backend tests
cd backend
uv run python manage.py test

# Frontend tests
cd frontend
npm run test

# Workflow tests
cd workflows
uv run pytest
```

### Database Migrations

```bash
cd backend

# Create migrations
uv run python manage.py makemigrations

# Apply migrations
uv run python manage.py migrate
```

### Admin Interface

Access Django admin at http://localhost:8000/admin after creating a superuser.

## 📄 Environment Variables

Create a `.env` file in the root directory:

```env
# Database
DB_NAME=vuln_hunter
DB_USER=vulnhunter
DB_PASSWORD=vulnhunter_dev
DB_HOST=localhost
DB_PORT=5432

# Django
DJANGO_SECRET_KEY=your-secret-key-here
DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ALLOWED_ORIGINS=http://localhost:3000

# Prefect
PREFECT_API_URL=http://localhost:4200/api

# AI/LLM
GEMINI_API_KEY=your-gemini-api-key

# Vulnerability DBs (optional)
VULNERS_API_KEY=your-vulners-key
```

## 🎯 Next Steps

1. Implement vulnerability database plugins (OSV.dev, NVD, Vulners)
2. Build Python code indexer with AST analysis
3. Set up LangChain AI agent with custom tools
4. Complete Django REST API endpoints
5. Build React UI components
6. Integrate Prefect workflows with Django backend
7. Add authentication and authorization
8. Implement caching and performance optimizations

## 📚 Documentation

See the `docs/` directory for more detailed documentation:
- [Architecture](docs/architecture.md)
- [Components](docs/components.md)

## 🤝 Contributing

This is a monorepo project. Please ensure:
- Backend code follows Django best practices
- Frontend uses React hooks and functional components
- Workflows use Prefect task decorators properly
- All shared models use Pydantic for validation
- Tests are included for new features

## 📝 License

[Add your license here]