# Contributing to e2e.dll

Thank you for your interest in contributing to e2e.dll! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- A clear, descriptive title
- Steps to reproduce the problem
- Expected vs actual behavior
- Your mIRC version and Windows version
- Any relevant log files from `e2e.logs`

### Suggesting Features

Feature suggestions are welcome! Please:
- Check if the feature has already been suggested
- Provide a clear use case
- Explain how it would benefit users
- Consider security implications

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Make your changes**:
   - Follow existing code style
   - Add comments for complex logic
   - Test thoroughly in mIRC
4. **Commit your changes**: Use clear, descriptive commit messages
5. **Push to your fork**: `git push origin feature/your-feature-name`
6. **Open a Pull Request**

### Code Guidelines

#### C Code (`e2e.c`, `e2e_keyex.c`)
- Use consistent indentation (tabs or 4 spaces)
- Check all DLL function return values for errors
- Use `ERROR:` prefix for error returns
- Add error logging for debugging
- Keep functions focused and modular

#### mIRC Script (`e2e.mrc`)
- Use meaningful variable names (`%net`, `%chan`, `%nick`)
- Add logging for important operations (`e2e_log`)
- Check for null/empty parameters
- Use helper functions to avoid code duplication
- Test in both channel and query contexts

### Security

- **Never commit keys or credentials**
- Report security vulnerabilities privately
- Use libsodium functions correctly
- Validate all user input
- Handle errors securely (fail-secure, not fail-open)

### Testing

Before submitting a PR, test:
- ✅ DM key exchange (offer, accept, reject)
- ✅ Channel key generation and sharing
- ✅ Encrypted message sending/receiving
- ✅ Auto-encrypt functionality
- ✅ Key persistence (DPAPI and password modes)
- ✅ Error handling (missing keys, invalid data)
- ✅ Menu actions work correctly

### Build Requirements

- Visual Studio 2022 or later (v143 toolset)
- libsodium 1.0.20 (included in repo)
- Win32 (32-bit) target platform

Build command:
```cmd
MSBuild e2e.vcxproj /p:Configuration=Release /p:Platform=Win32
```

### Documentation

When adding features:
- Update `README.md` with usage examples
- Update command list in `e2e.mrc` header
- Update `/e2e help` output if needed

## Code of Conduct

Be respectful and constructive. We're all here to improve mIRC security together.

## Questions?

If you have questions about contributing, feel free to open an issue with the `question` label.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see LICENSE.txt).
