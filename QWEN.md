# SmartCard Master Skills - QWEN.md

## Project Overview

SmartCard Master Skills is a Python-based framework for building SmartCard Agent Skills. It provides a complete infrastructure for developing, testing, and deploying smartcard operations as independent skills that communicate with an Agent Runtime via stdin/stdout JSON-RPC protocol.

### Key Features

- **uv Workspace Architecture**: Multi-module project using uv workspaces for dependency management
- **Skill SDK**: Core framework for building skills with protocol models, session management, and abstract base classes
- **Card Reader Module**: Reader connection and APDU communication with T=0/T=1 protocol support
- **Pre-built Skills**: Read ICCID and eSIM IoT Profile Download (SGP.33) skills included
- **Comprehensive Testing**: Protocol, session, ASN.1 codec, state machine, and real card tests

### Technology Stack

- **Python 3.11+**
- **uv** - Package and workspace management
- **pydantic** - Data validation
- **pyasn1** - ASN.1 encoding/decoding
- **pyscard** - Smart card communication
- **pytest** - Testing framework
- **cryptography** - Cryptographic operations

## Project Structure

```
smartcard-master-skills/
├── packages/                    # Core packages
│   ├── skill-sdk/              # SmartCard Skill SDK (protocol, session, base classes)
│   └── card-reader/            # Reader connection and APDU communication
├── skills/                      # Skill implementations
│   ├── read-iccid/             # Read SIM card ICCID skill
│   └── esim-iot-profile-download/  # eSIM Profile download skill (SGP.33)
├── tests/                       # Test suite
├── docs/                        # Documentation
├── pyproject.toml              # Root workspace configuration
└── README.md                   # Project overview
```

## Building and Running

### Prerequisites

- Python >= 3.11
- uv (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/wangshengjun1134/smartcard-master-skills.git
cd smartcard-master-skills

# Install all workspace dependencies
uv sync
```

### Running Tests

```bash
# Run all tests
uv run pytest -v

# Run specific test files
uv run pytest tests/test_read_iccid.py -v
uv run pytest tests/test_esim_iot_profile_download.py -v
uv run pytest tests/test_protocol.py -v
uv run pytest tests/test_session.py -v

# Run real card tests (requires card reader hardware)
uv run pytest tests/test_card_reader.py -v
uv run pytest tests/test_esim_real_card.py -v
```

### Running Individual Skills

```bash
# Run Read ICCID skill
uv run --package read-iccid-skill read-iccid-skill

# Run eSIM Profile Download skill
uv run --package esim-iot-profile-download-skill esim-iot-profile-download-skill
```

## Core Components

### 1. SmartCard Skill SDK (`packages/skill-sdk`)

The SDK provides the foundation for building skills:

- **`protocol.py`**: Core data structures (Action, ActionResult, SkillResult, SkillSession)
- **`session_store.py`**: Session management (SkillSession, SessionStore)
- **`base.py`**: Abstract base classes (Skill, SkillContext, OutputCollector)
- **`simple_apdu.py`**: Simplified base class for single-APDU skills (SimpleApduSkill)

### 2. Card Reader (`packages/card-reader`)

Handles reader connection and APDU communication:

- T=0/T=1 protocol auto-selection
- Automatic handling of 61XX (GET RESPONSE) and 91XX (FETCH) responses
- Context manager support
- Comprehensive error handling

### 3. Read ICCID Skill (`skills/read-iccid`)

Three-step APDU flow to read SIM card ICCID:

1. SELECT MF (Master File)
2. SELECT EF_ICCID
3. READ BINARY with BCD decoding

### 4. eSIM IoT Profile Download Skill (`skills/esim-iot-profile-download`)

Complete SGP.33 profile download and enable implementation:

- Full state machine (22+ states)
- Pre-download cleanup (EuiccMemoryReset, ListNotification, RemoveNotification)
- Profile installation (AuthenticateServer, PrepareDownload, LoadProfilePackage)
- eIM enablement (AddInitialEim, EnablePSMO)
- ASN.1 encoding/decoding
- Resource management (certificates, profile packages)

## Development Conventions

### Creating a New Skill

1. Create a new directory under `skills/`
2. Create `pyproject.toml` with workspace dependency reference
3. Implement the skill class (inherit from `Skill` or `SimpleApduSkill`)
4. Create `SKILL.md` documentation
5. Write test cases in `tests/`

### Skill Communication Protocol

Skills communicate with the Agent Runtime via stdin/stdout using JSON-RPC 2.0:

```json
// Initialization
{"jsonrpc": "2.0", "id": "1", "method": "skill.init", "params": {...}}

// Start execution
{"jsonrpc": "2.0", "id": "2", "method": "skill.start", "params": {"sessionId": "..."}}

// Handle action result
{"jsonrpc": "2.0", "id": "3", "method": "skill.handleActionResult", "params": {...}}
```

### Skill Status Flow

- `INITIALIZED`: Initialization complete
- `CONTINUE`: Requires next action execution
- `SUCCESS`: Execution successful
- `FAILED`: Execution failed
- `NEED_INPUT`: Requires user input

### Code Style

- Use type hints for all function signatures
- Follow existing naming conventions (snake_case for functions/variables, PascalCase for classes)
- Keep skills focused on protocol logic; delegate hardware access to Runtime
- Never directly access card readers from skills
- Never output sensitive data (keys, PINs) to stdout
- Use stderr for logging and debugging

### Testing Practices

- Write protocol conformance tests for all skills
- Test session management and state transitions
- Include ASN.1 codec tests for encoding/decoding
- Provide both mock tests and real card tests
- Ensure all tests pass before committing: `uv run pytest -v`

### Security Guidelines

- Never output encryption keys, MAC keys, or PINs in plaintext
- Mark sensitive actions with `sensitive: true`
- Desensitize logs and trace output
- Use secure references or encryption for sensitive session data
- Set appropriate file permissions (0600 for session files, 0700 for session directories)

## Key Design Principles

1. **Separation of Concerns**: Skills handle protocol logic; Runtime handles hardware access
2. **Session Management**: Skills maintain state via local session files (not in Git)
3. **No LLM During Execution**: Agent LLM only involved in initial parameter collection or NEED_INPUT scenarios
4. **Direct Mode Support**: Skills can be invoked directly via special commands, bypassing LLM
5. **Output vs Result Separation**: Process output goes to UI; results control flow
6. **Security First**: Sensitive data must be desensitized; session files secured

## Documentation

- [Skill Design Document](docs/skill-design.md) - Complete architecture and design specification
- [Implementation Plan](docs/implementation-plan.md) - Implementation task breakdown
- [Read ICCID SKILL.md](skills/read-iccid/SKILL.md) - ICCID skill documentation
- [eSIM Profile Download SKILL.md](skills/esim-iot-profile-download/SKILL.md) - eSIM download skill documentation

## Contributing

- Follow existing code style and conventions
- Write tests for new features
- Update documentation as needed
- Run `uv run pytest -v` before committing
- Submit issues and pull requests via GitHub

## License

MIT
