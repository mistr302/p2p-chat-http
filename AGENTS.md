# Repository Guidelines

## Project Structure & Module Organization
This repository is currently a skeleton with no tracked source files or directories. When adding code, keep a conventional layout so contributors can orient quickly. A typical structure would be:
- `src/` for application code.
- `tests/` for automated tests.
- `scripts/` for helper tooling.
- `assets/` for static files if the project needs them.

If you introduce a different layout, document it here and keep directory names consistent.

## Build, Test, and Development Commands
No build or runtime commands are defined yet. When you add tooling, document the exact commands and what they do. Examples to follow:
- `npm run dev` to run a local dev server.
- `npm test` to run the test suite.
- `make build` to produce a release artifact.

## Coding Style & Naming Conventions
No style guide is present. Until tooling exists, follow these defaults:
- 2-space indentation for web or JavaScript/TypeScript projects, 4-space for Python.
- `lower_snake_case` for files in Python; `kebab-case` for web assets; `UpperCamelCase` for class names.
- Keep functions small and name them by behavior (e.g., `fetch_messages`, `render_chat_view`).

When you add a formatter or linter (e.g., Prettier, ESLint, Black), document the command and configuration.

## Testing Guidelines
No test framework is configured. If you add tests, place them in `tests/` and follow the framework’s naming conventions (e.g., `test_*.py`, `*.spec.ts`). Document how to run the tests and any coverage expectations.

## Commit & Pull Request Guidelines
There is no commit convention visible yet. Use clear, imperative commit messages (e.g., “Add HTTP transport layer”). For pull requests, include:
- A short summary of changes.
- Linked issues (if any).
- Screenshots or logs when UI or behavior changes.

## Security & Configuration Tips
Avoid committing secrets. If configuration is needed, use a `.env.example` file and document required variables in this guide.
