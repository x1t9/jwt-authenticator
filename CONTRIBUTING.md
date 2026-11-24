# Contributing to JWT Authenticator

Thank you for your interest in contributing! This project is MIT-licensed and welcomes all contributions.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/jwt-authenticator.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`

## Development Setup

**Requirements:**
- PHP 8.0+
- WordPress 5.0+
- Composer (for PHP dependencies)

**Install dependencies:**
```bash
cd includes
composer install
```

## Code Style

- Follow [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/php/)
- Use tabs for indentation (not spaces)
- Add PHPDoc blocks to all public methods
- Keep code compatible with the minimum PHP version (8.0).

## Submitting Changes

1. Ensure your code passes PHP linting: `php -l your-file.php`
2. Update `CHANGELOG.md` with your changes under `[Unreleased]`
3. Push your branch and open a Pull Request against `main`
4. Describe what your PR does and reference any related issues

## Reporting Bugs

Open a [GitHub Issue](https://github.com/x1t9/jwt-authenticator/issues) with:
- WordPress version
- PHP version
- Steps to reproduce
- Expected vs actual behavior

## Feature Requests

Open a GitHub Issue with the `enhancement` label and describe the use case.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
