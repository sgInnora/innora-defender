# Contributing to Innora-Defender

Thank you for considering contributing to Innora-Defender! Your contributions help make our ransomware defense system better for everyone.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct. Please report unacceptable behavior to [info@innora.ai].

## How Can I Contribute?

### Reporting Bugs

- Check if the bug has already been reported in the Issues section
- Use the bug report template to create a new issue
- Include detailed steps to reproduce the bug
- Include any relevant logs or screenshots
- Specify your environment (OS, Python version, etc.)

### Suggesting Enhancements

- Check if the enhancement has already been suggested in the Issues section
- Use the feature request template to create a new issue
- Clearly describe the enhancement and the problem it solves
- Include examples of how the enhancement would be used

### Pull Requests

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Pull Request Guidelines

- Update documentation for any changed functionality
- Add or update tests as needed
- Ensure your code passes all tests
- Follow the existing code style
- Keep pull requests focused on a single concern
- Link to any relevant issues

## Development Environment

1. Clone the repository
2. Create a virtual environment
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

## Testing

- Run tests with `pytest`
- Run tests with coverage: `pytest --cov=./`

## Documentation

- Update documentation for any changed functionality
- Follow the existing documentation style
- Use proper grammar and clear language

## Code Style

This project follows PEP 8 style guidelines. Use tools like flake8 and black to ensure your code meets these standards:

```bash
# Check code style
flake8 .

# Format code
black .
```

## Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

## Licensing

By contributing to Innora-Defender, you agree that your contributions will be licensed under the project's MIT license.

---

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)