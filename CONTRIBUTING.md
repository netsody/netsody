# Contributing to drasyl

This is a short guide on how to contribute things to drasyl.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Reporting a bug](#reporting-a-bug)
- [Requesting a feature](#requesting-a-feature)
- [Submitting a pull request](#submitting-a-pull-request)
- [Code Style and Guidelines](#code-style-and-guidelines)
- [Testing](#testing)
- [Documentation](#documentation)
- [License](#license)

## Getting Started

Before you begin contributing, please make sure you have:

- Rust toolchain installed (latest stable version recommended)
- Git installed
- Basic understanding of the drasyl project structure

## Development Setup

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/drasyl-rs.git
   cd drasyl-rs
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/original-repo/drasyl-rs.git
   ```
4. Install dependencies:
   ```bash
   cargo build
   ```

## Reporting a bug

When filing an issue, please include the following information if possible as well as a description
of the problem. Make sure you test with
the latest version of drasyl:

* drasyl version
* Operating system and version
* Expected behavior
* Actual behavior
* Steps to reproduce
    * Bonus points: provide a minimal working example
* Error messages or logs (if applicable)

### Important: "Getting Help Vs Reporting an Issue"

The issue tracker is not a general support forum, but a place to report bugs and asks for new
features.

For end-user related support questions, try using first:

- the drasyl Discord: [![Discord](https://img.shields.io/discord/959492172560891905)](https://discord.gg/2tcZPy7BCu)

## Requesting a feature

When requesting a new feature, please:

1. Check if the feature has already been requested
2. Provide a clear description of the feature
3. Explain why this feature would be useful
4. If possible, provide examples of how it would be used

## Submitting a pull request

If you find a bug that you'd like to fix, or a new feature that you'd like to implement then please
submit a pull request/merge request.

If it is a big feature then make an issue first so it can be discussed.

First, create a fork via GitHub's/GitLab's Web Interface.

Now in your terminal, git clone your fork.

And get hacking.

Make sure you

* Add [changelog](./CHANGELOG.md) entry
* Add documentation for a new feature.
* Add tests for a new feature.
* squash commits down to one per feature.
* rebase to master with `git rebase master`
* keep your pull request/merge request as small as possible.

When ready - run the tests

    cargo test

When you are done with that git push your changes.

Go to the GitHub website and click "New pull request".

Your patch will get reviewed and you might get asked to fix some stuff.

If so, then make the changes in the same branch, squash the commits (make multiple commits one
commit) by running:

```
git log # See how many commits you want to squash
git reset --soft HEAD~2 # This squashes the 2 latest commits together.
git status # Check what will happen, if you made a mistake resetting, you can run git reset 'HEAD@{1}' to undo.
git commit # Add a new commit message.
git push --force # Push the squashed commit to your fork repo.
```

## Code Style and Guidelines

### Rust Code Style

- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/style/naming/README.html)
- Use `rustfmt` to format your code:
  ```bash
  cargo fmt
  ```
- Run `clippy` to check for common issues:
  ```bash
  cargo clippy
  ```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run benchmarks
cargo bench
```

### Writing Tests

- Write unit tests for new functionality
- Include integration tests for public APIs
- Ensure tests are deterministic and don't depend on external state
- Use descriptive test names that explain what is being tested

## Documentation

### Code Documentation

- Document all public APIs with doc comments
- Include examples in documentation where appropriate
- Keep documentation up to date with code changes

### README Updates

- Update README files if you add new features or change existing behavior
- Include usage examples for new functionality

## License

Any contributions you make will be under the [MIT License](./LICENSE)

In short, when you submit code changes, your submissions are assumed to be under the same MIT
license that covers the project. Feel free to contact the maintainers if this is an issue for you.

## Getting Help

If you need help with contributing:

1. Check existing issues and pull requests
2. Join the Discord community
3. Create an issue for questions about the contribution process

## Recognition

Contributors will be recognized in the project's release notes. Thank you for contributing to drasyl!