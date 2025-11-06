# Configuration Overview for scan_repos.py

All configuration is done through `config.json`. Copy `config.example.json` to `config.json` and update it with your settings.

## Configuration Structure

The config file is organized into three main sections:

### 1. LM Studio Configuration

```json
"lm_studio": {
  "base_url": "http://localhost:1234/v1",
  "api_key": "lm-studio"
}
```

**Settings:**

- `base_url`: The API endpoint for your LM Studio server
  - Default: `http://localhost:1234/v1`
  - If LM Studio is running on a different port, update this URL
  - Example: `http://localhost:8080/v1` if using port 8080
- `api_key`: The API key for LM Studio (usually `"lm-studio"`)

### 2. Model Configuration

```json
"model": {
  "name": "local-model",
  "temperature": 0.1,
  "max_tokens": 2000
}
```

**Settings:**

- `name`: The exact model name as shown in LM Studio
  - Examples: `"deepseek-coder-33b-instruct"`, `"codellama-34b-instruct"`, `"qwen2.5-coder-32b-instruct"`
  - Must match exactly what you see in LM Studio's model list
- `temperature`: Controls randomness in model responses
  - Range: 0.0 to 2.0
  - Lower (0.0-0.3): More consistent, deterministic responses
  - Higher (0.7-2.0): More creative, varied responses
  - Recommended: 0.1 for code analysis (more consistent results)
- `max_tokens`: Maximum length of the model's response
  - Default: 2000
  - Increase if you expect longer analysis results
  - Decrease if you're running out of memory

### 3. Scan Configuration

```json
"scan": {
  "root_directory": "/path/to/your/repos",
  "extensions": [".py", ".js", ".jsx", ".tsx"],
  "exclude_dirs": ["build", "node_modules", ".git", "__pycache__", "dist", "venv", ".venv", "env"],
  "save_interval": 10
}
```

**Settings:**

- `root_directory`: Path to the directory containing your repositories
  - Examples:
    - macOS/Linux: `"/Users/yourname/repos"` or `"/home/yourname/projects"`
    - Windows: `"C:\\Users\\yourname\\code"`
  - Use forward slashes on all platforms, or escaped backslashes on Windows
- `extensions`: File extensions to scan (as an array)
  - Default: `[".py", ".js", ".jsx", ".tsx"]`
  - Add more: `[".py", ".js", ".jsx", ".tsx", ".go", ".rb", ".java", ".ts"]`
  - Only files with these extensions will be analyzed
- `exclude_dirs`: Directories to skip during scanning (as an array)
  - Default includes: `build`, `node_modules`, `.git`, `__pycache__`, `dist`, `venv`, `.venv`, `env`
  - Add more: `["build", "node_modules", ".git", "__pycache__", "dist", "venv", ".venv", "env", "tmp", "cache", "logs"]`
  - These directories and their contents will be completely skipped
- `save_interval`: How often to save scan state (in number of files)
  - Default: `10` (saves after every 10 files)
  - Higher values (e.g., `50`): Less frequent saves, slightly faster, but more progress lost if interrupted
  - Lower values (e.g., `1`): Saves after every file, safest but slower
  - Recommended: `10` for most use cases

## Quick Setup

1. Copy the example config:

   ```bash
   cp config.example.json config.json
   ```

2. Edit `config.json` with your settings:
   - Set `lm_studio.base_url` to match your LM Studio port
   - Set `model.name` to your loaded model name
   - Set `scan.root_directory` to your repos directory

3. Run the scanner:

   ```bash
   python scan_repos.py
   ```

## Tips

- **Model name**: Must match exactly what's shown in LM Studio (case-sensitive)
- **Root directory**: Use absolute paths for reliability
- **Save interval**: For large codebases, `10` is a good balance between safety and speed
- **Extensions**: Only add extensions you actually want to scan to improve performance
- **Exclude dirs**: Be thorough here to avoid scanning build artifacts and dependencies
