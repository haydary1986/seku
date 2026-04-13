# Contributing to Seku

Thank you for your interest in contributing to Seku! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/haydary1986/seku/issues) to avoid duplicates
2. Use the bug report template when creating a new issue
3. Include steps to reproduce, expected behavior, and actual behavior
4. Add screenshots or logs if applicable

### Suggesting Features

1. Open a [feature request issue](https://github.com/haydary1986/seku/issues/new)
2. Describe the use case and expected behavior
3. Explain why this feature would be useful to other users

### Submitting Code

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
3. **Make your changes** following the coding standards below
4. **Test** your changes thoroughly
5. **Commit** using [conventional commits](https://www.conventionalcommits.org/):
   ```
   feat: add new scanner for subresource integrity
   fix: correct SSL score calculation for expired certs
   docs: update API reference with new endpoints
   ```
6. **Push** and open a Pull Request against `main`

## Development Setup

### Prerequisites

- Go 1.25+
- Node.js 20+
- Docker (optional, for containerized development)

### Running Locally

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/seku.git
cd seku

# Backend
cd backend
go run ./cmd/main.go

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

The backend runs on `http://localhost:8080` and the frontend on `http://localhost:5173`.

Default credentials: `admin` / `admin123`

## Coding Standards

### Backend (Go)

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use meaningful variable and function names
- Add comments for exported functions
- Handle all errors explicitly
- Write tests for new scanners and API endpoints

### Frontend (Vue.js)

- Use Composition API with `<script setup>`
- Follow Vue.js style guide (Priority A and B rules)
- Use Tailwind CSS utility classes for styling
- Keep components focused and under 400 lines

### Adding a New Scanner

1. Create `backend/internal/scanner/your_scanner.go`
2. Implement the scanner interface with `Scan()` method
3. Register the scanner in `scanner.go`
4. Add OWASP/CWE mappings in `owasp.go`
5. Add remediation steps in `remediation.go`
6. Write tests in `your_scanner_test.go`

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include a clear description of what changed and why
- Reference related issues (e.g., "Closes #42")
- Ensure all existing tests pass
- Add tests for new functionality
- Update documentation if the public API changes

## Questions?

Open a [discussion](https://github.com/haydary1986/seku/discussions) or reach out via issues.

---

Thank you for helping make the web more secure!
