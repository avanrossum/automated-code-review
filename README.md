# Code Scanner - Local LLM Security & Pattern Analysis

A resumable code scanner that uses local LLM models (via LM Studio) to identify security issues, bad patterns, and regressions across large codebases.

## Features

- ✅ **Resumable**: Tracks exact position in directory tree, can be interrupted and resumed
- ✅ **Intelligent skipping**: Only scans files that have changed (via content hashing)
- ✅ **Crash-safe**: Saves state periodically and on interruption
- ✅ **Progress tracking**: Detailed logging of scan progress
- ✅ **Multiple file types**: Scans Python (.py), JavaScript (.js), React (.jsx, .tsx)
- ✅ **Smart exclusions**: Automatically skips build dirs, node_modules, etc.

## Prerequisites

1. **LM Studio** - Download from https://lmstudio.ai/
2. **Python 3.7+** with pip
3. **A local LLM model** - Recommended:
   - DeepSeek Coder V2 (16B or 33B)
   - CodeLlama 34B
   - Qwen2.5-Coder (7B-32B)
   - Mistral/Mixtral

## Setup

### 1. Install Python dependencies

```bash
pip install openai
```

### 2. Load a model in LM Studio

1. Open LM Studio
2. Download a code-focused model (see recommendations above)
3. Load the model and start the local server
4. Note the API endpoint (usually `http://localhost:1234/v1`)

### 3. Configure the scanner

Copy the example config file and update it with your settings:

```bash
cp config.example.json config.json
```

Then edit `config.json` with your configuration:

```json
{
  "lm_studio": {
    "base_url": "http://localhost:1234/v1",
    "api_key": "lm-studio"
  },
  "model": {
    "name": "your-model-name",
    "temperature": 0.1,
    "max_tokens": 2000
  },
  "scan": {
    "root_directory": "/path/to/your/repos",
    "extensions": [".py", ".js", ".jsx", ".tsx"],
    "exclude_dirs": ["build", "node_modules", ".git", "__pycache__"],
    "save_interval": 10
  }
}
```

**Important settings:**
- `lm_studio.base_url`: Your LM Studio API endpoint (usually `http://localhost:1234/v1`)
- `model.name`: The exact model name as shown in LM Studio
- `scan.root_directory`: Path to the directory containing your repositories

## Usage

### Start or resume a scan

```bash
python scan_repos.py
```

Press `Ctrl+C` at any time to pause. Run the same command to resume exactly where you left off.

### Check scan status

```bash
python scan_repos.py status
```

Shows:
- When scan started
- Current position (folder/file)
- Number of folders completed
- Files scanned/skipped
- Whether scan is complete or in progress

### Generate report from findings

```bash
python scan_repos.py report
```

Generates `code_analysis_report.md` from existing findings without re-scanning.

## Output Files

- **`scan_state.json`** - Tracks position in directory tree, resumption point
- **`code_analysis_findings.json`** - All findings with file hashes and timestamps
- **`scan_progress.log`** - Human-readable log with timestamps
- **`code_analysis_report.md`** - Final report organized by severity

## How It Works

1. **Directory walking**: Recursively walks through your repos
2. **Smart filtering**: Only scans `.py`, `.js`, `.jsx`, `.tsx` files
3. **Exclusion handling**: Skips `build/`, `node_modules/`, `.git/`, etc.
4. **Content hashing**: MD5 hash of each file to detect changes
5. **LLM analysis**: Sends each file to local LLM for analysis
6. **State tracking**: Saves progress after every 10 files
7. **Result aggregation**: Collects all findings into structured JSON
8. **Report generation**: Creates markdown report organized by severity

## Customization

All configuration is done through `config.json`. Edit it to customize:

### Scan different file types

Edit the `extensions` array in `config.json`:

```json
"extensions": [".py", ".js", ".jsx", ".tsx", ".go", ".rb", ".java"]
```

### Exclude additional directories

Edit the `exclude_dirs` array in `config.json`:

```json
"exclude_dirs": ["build", "node_modules", ".git", "__pycache__", "dist", "venv", ".venv", "env", "tmp", "cache"]
```

### Adjust save frequency

Edit `save_interval` in `config.json`:

```json
"save_interval": 50  // Save state every 50 files (default: 10)
```

### Adjust model parameters

Edit the `model` section in `config.json`:

```json
"model": {
  "name": "your-model-name",
  "temperature": 0.2,  // Lower = more consistent, Higher = more creative
  "max_tokens": 4000    // Maximum response length
}
```

### Customize the analysis prompt

Edit the `scan_file()` function in `scan_repos.py` (around line 85) to focus on specific issues:

```python
prompt = f"""Analyze this code focusing on:
1. SQL injection vulnerabilities
2. XSS vulnerabilities  
3. Hardcoded secrets/credentials
4. Insecure authentication patterns

Return ONLY valid JSON...
```

## Tips for Large Codebases

- **Run overnight**: For millions of lines, this will take hours/days
- **Monitor GPU usage**: Watch LM Studio to ensure model is actually running
- **Check logs regularly**: `tail -f scan_progress.log` to monitor progress
- **Resume frequently**: Safe to Ctrl+C and resume as needed
- **Adjust model size**: Larger models = better results but slower scans

## Troubleshooting

### "Connection refused" error

- Ensure LM Studio server is running
- Check the `lm_studio.base_url` in `config.json`

### JSON decode errors

- Some models don't always output valid JSON
- Try a different model or adjust the prompt
- Check `scan_progress.log` for details

### Very slow scanning

- Model might be too large for your hardware
- Try a smaller model (7B instead of 34B)
- Close other GPU-intensive applications

### Out of memory errors

- Reduce model size in LM Studio
- Reduce `max_tokens` in `config.json` (model section)
- Process fewer files at once

## License

Free to use and modify as needed.

## Support

For issues specific to:
- LM Studio: https://lmstudio.ai/docs
- OpenAI client: https://github.com/openai/openai-python
- This scanner: Check the code comments or modify as needed
