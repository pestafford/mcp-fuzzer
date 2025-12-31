# Publishing MCP Fuzzer to PyPI

## Prerequisites

### 1. Create PyPI Accounts

**Production PyPI** (for real releases):
- Go to https://pypi.org/account/register/
- Create account and verify email

**Test PyPI** (for testing - recommended first):
- Go to https://test.pypi.org/account/register/
- Create account and verify email

### 2. Create API Tokens

**For Test PyPI**:
1. Go to https://test.pypi.org/manage/account/token/
2. Click "Add API token"
3. Token name: `mcp-fuzzer-test`
4. Scope: "Entire account" (or specific to project after first upload)
5. Copy the token (starts with `pypi-`)

**For Production PyPI**:
1. Go to https://pypi.org/manage/account/token/
2. Click "Add API token"
3. Token name: `mcp-fuzzer`
4. Scope: "Entire account" (or specific to project after first upload)
5. Copy the token (starts with `pypi-`)

### 3. Install Build Tools

```bash
pip install --upgrade build twine
```

## Publishing Process

### Step 1: Clean Previous Builds

```bash
cd ~/projects/mcp-fuzzer
rm -rf dist/ build/ *.egg-info
```

### Step 2: Build the Package

```bash
python -m build
```

This creates:
- `dist/mcp_fuzzer-1.0.0-py3-none-any.whl` (wheel distribution)
- `dist/mcp-fuzzer-1.0.0.tar.gz` (source distribution)

### Step 3: Test Upload to Test PyPI (RECOMMENDED)

```bash
# Upload to Test PyPI
python -m twine upload --repository testpypi dist/*
```

When prompted:
- Username: `__token__`
- Password: Your Test PyPI API token (including the `pypi-` prefix)

**Or use token directly**:
```bash
python -m twine upload --repository testpypi dist/* \
  --username __token__ \
  --password pypi-YOUR_TEST_TOKEN_HERE
```

### Step 4: Test Installation from Test PyPI

```bash
# Create test environment
python -m venv /tmp/test-mcp-fuzzer
source /tmp/test-mcp-fuzzer/bin/activate

# Install from Test PyPI
pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  mcp-fuzzer

# Test the installation
mcp-fuzzer --version
mcp-fuzzer --list-categories

# Clean up
deactivate
rm -rf /tmp/test-mcp-fuzzer
```

### Step 5: Upload to Production PyPI

**Only do this after verifying Test PyPI works!**

```bash
# Upload to production PyPI
python -m twine upload dist/*
```

When prompted:
- Username: `__token__`
- Password: Your PyPI API token (including the `pypi-` prefix)

**Or use token directly**:
```bash
python -m twine upload dist/* \
  --username __token__ \
  --password pypi-YOUR_PRODUCTION_TOKEN_HERE
```

### Step 6: Verify Production Installation

```bash
# Install from PyPI
pip install mcp-fuzzer

# Test
mcp-fuzzer --version
```

## Using .pypirc (Optional - Saves Tokens)

Create `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-YOUR_PRODUCTION_TOKEN

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-YOUR_TEST_TOKEN
```

**Important**: Set proper permissions:
```bash
chmod 600 ~/.pypirc
```

Then you can upload without entering credentials:
```bash
# Upload to Test PyPI
python -m twine upload --repository testpypi dist/*

# Upload to Production PyPI
python -m twine upload dist/*
```

## Quick Reference Commands

```bash
# 1. Clean
rm -rf dist/ build/ *.egg-info

# 2. Build
python -m build

# 3. Check package
python -m twine check dist/*

# 4. Upload to Test PyPI
python -m twine upload --repository testpypi dist/*

# 5. Upload to Production PyPI
python -m twine upload dist/*
```

## Troubleshooting

### "File already exists"

PyPI doesn't allow re-uploading the same version. You must:
1. Bump version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Rebuild and upload

### "Invalid authentication credentials"

- Make sure username is `__token__` (not your PyPI username)
- Token must include the `pypi-` prefix
- Check token hasn't expired

### "Package name already taken"

If `mcp-fuzzer` is taken, consider:
- `mcp-security-fuzzer`
- `modelcontextprotocol-fuzzer`
- `credence-mcp-fuzzer`

### Missing Dependencies

If users can't install:
```bash
# Check dependencies in pyproject.toml
# Make sure mcp>=0.9.0 is listed
```

## After Publishing

### 1. Add PyPI Badge to README

```markdown
[![PyPI version](https://badge.fury.io/py/mcp-fuzzer.svg)](https://badge.fury.io/py/mcp-fuzzer)
[![Downloads](https://pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/project/mcp-fuzzer)
```

### 2. Update GitHub README

Add installation instructions:
```markdown
## Installation

```bash
pip install mcp-fuzzer
```
```

### 3. Create GitHub Release

```bash
gh release create v1.0.0 \
  --title "MCP Fuzzer v1.0.0" \
  --notes "Initial production release - see CHANGELOG.md"
```

### 4. Announce

- Tweet about it
- Post on Reddit (r/Python, r/cybersecurity)
- Share in MCP community Discord/forums
- Add to awesome-mcp lists

## Future Releases

For version 1.0.1, 1.1.0, etc.:

```bash
# 1. Update version in pyproject.toml
# 2. Update CHANGELOG.md
# 3. Commit changes
git add pyproject.toml CHANGELOG.md
git commit -m "Bump version to 1.0.1"
git tag v1.0.1
git push && git push --tags

# 4. Build and upload
rm -rf dist/
python -m build
python -m twine upload dist/*

# 5. Create GitHub release
gh release create v1.0.1 \
  --title "MCP Fuzzer v1.0.1" \
  --notes "See CHANGELOG.md for details"
```

## Security Note

**Never commit tokens to git!**

Add to `.gitignore`:
```
.pypirc
*.token
```
