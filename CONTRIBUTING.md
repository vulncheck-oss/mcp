# Contributing

## Getting started

1. Fork the repository and create a branch from `main`
2. Make your changes
3. Ensure tests and lint pass: `make test && make lint`
4. Open a pull request

For significant changes, open an issue first to discuss the approach.

## Commit style

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Use prefixes like `feat:`, `fix:`, `docs:`, `chore:`, etc.

## Requirements

- Go 1.26+
- A VulnCheck API token for integration testing

## Submitting a pull request

1. Create a new branch: git checkout -b my-branch-name
2. Make your change, add tests, and ensure tests pass
3. Update any relevant documentation
4. Submit a pull request: gh pr create --web