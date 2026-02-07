# Infurnex

**Infurnex** is a secure Linux AI agent that lets you interact with your system using natural language. It intelligently decides whether to answer conversationally or execute system commands based on your input.

## Features

- 🤖 **Intelligent Command Routing**: Automatically determines if your query needs system access
- 🔒 **Security First**: Built-in command sanitization and sudo confirmation
- 🌐 **Local LLM Support**: Works with LM Studio and other OpenAI-compatible endpoints
- ♻️ **Auto-Retry**: Automatically retries failed commands with alternative approaches
- 🎯 **Clean Output**: Minimal, distraction-free interface

## Architecture

Infurnex uses a multi-agent workflow:

1. **Decider Agent**: Determines if the query requires system access
2. **Chat Agent**: Handles conversational queries without system interaction
3. **Planner Agent**: Converts requests into safe shell commands
4. **Executor**: Runs commands with built-in safety checks

## Installation

### Prerequisites

- Python 3.8+
- LM Studio or OpenAI-compatible API endpoint
- CAI SDK: `pip install cai-sdk`

### Setup

1. Clone the repository:
```bash
git clone https://github.com/MoghulKannan-N/infurnex.git
cd infurnex
```

2. Configure your LLM endpoint in `main.py`:
```python
os.environ["OPENAI_BASE_URL"] = "http://YOUR_IP:1234/v1"
```

3. Run Infurnex:
```bash
python3 main.py
```

## Usage

```
infurnex successfully booted...! >>

@ >> what directory am i in
infurnex> /home/user/projects

@ >> list files here
infurnex> (command output)

@ >> what is linux
infurnex> Linux is an open-source operating system...
```

## Configuration

### Environment Variables

- `OPENAI_BASE_URL`: Your LLM API endpoint
- `CAI_MODEL`: Model name (default: `openai/mistral-7b-instruct-v0.3`)
- `CAI_STREAM`: Enable/disable streaming (default: `false`)
- `CAI_TELEMETRY`: Enable/disable telemetry (default: `false`)

### Security Settings

- Sudo commands require user confirmation
- Command sanitization prevents dangerous patterns
- Working directory state maintained across sessions

## Project Structure

```
infurnex/
├── main.py              # Main application entry point
├── agents/              # Agent definitions
│   ├── chat.py
│   ├── decider.py
│   └── planner.py
├── prompts/             # System prompts
│   ├── decider.txt
│   ├── planner.txt
│   └── responder.txt
├── tools/               # Tool definitions
│   └── run_command.py
└── policy/              # Security policies
    └── whitelist.py
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - See LICENSE file for details

## Author

**MoghulKannan-N**

---

*Built with ❤️ using CAI SDK and local LLMs*
