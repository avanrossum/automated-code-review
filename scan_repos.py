import os
import json
from pathlib import Path
from openai import OpenAI, APIConnectionError, APIError, APITimeoutError
import hashlib
from datetime import datetime
import time
import sys
import re

# State tracking files
STATE_FILE = "scan_state.json"
FINDINGS_DB = "code_analysis_findings.json"
PROGRESS_LOG = "scan_progress.log"
CONFIG_FILE = "config.json"

def load_config():
    """Load configuration from config.json, or exit with helpful message"""
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ Error: {CONFIG_FILE} not found!")
        print(f"   Please copy config.example.json to {CONFIG_FILE} and update it with your settings.")
        print(f"   Example: cp config.example.json {CONFIG_FILE}")
        sys.exit(1)
    
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
    
    return config

# Load configuration
config = load_config()
client = OpenAI(
    base_url=config['lm_studio']['base_url'],
    api_key=config['lm_studio']['api_key']
)

def load_state():
    """Load scanning state - tracks progress through directory tree"""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {
        'last_scanned_folder': None,
        'last_scanned_file': None,
        'completed_folders': [],
        'last_run': None,
        'total_files_scanned': 0,
        'total_files_skipped': 0,
        'scan_start_time': None
    }

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def load_findings():
    if os.path.exists(FINDINGS_DB):
        with open(FINDINGS_DB, 'r') as f:
            return json.load(f)
    return {}

def save_findings(findings):
    with open(FINDINGS_DB, 'w') as f:
        json.dump(findings, f, indent=2)

def log_progress(message):
    """Append to progress log with timestamp"""
    timestamp = datetime.now().isoformat()
    log_line = f"[{timestamp}] {message}\n"
    print(log_line.strip())
    with open(PROGRESS_LOG, 'a') as f:
        f.write(log_line)

def get_file_hash(content):
    return hashlib.md5(content.encode()).hexdigest()

def should_scan(file_path, content, findings_db):
    """Check if we've already scanned this exact content"""
    if file_path not in findings_db:
        return True
    file_hash = get_file_hash(content)
    return findings_db[file_path].get('hash') != file_hash

def extract_json_block(text: str) -> str | None:
    """Extract first balanced JSON object from text"""
    # Strip code fences
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE)
    # Find first balanced JSON object
    start = text.find('{')
    if start == -1:
        return None
    depth = 0
    for i, ch in enumerate(text[start:], start=start):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return text[start:i+1]
    return None

def try_parse_json(s: str) -> dict | None:
    """Try to parse JSON, return None on failure"""
    try:
        return json.loads(s)
    except Exception:
        return None

def looks_binary(content: str) -> bool:
    """Check if content looks like binary data"""
    sample = content[:4096]
    weird = sum(1 for ch in sample if ord(ch) == 0 or ord(ch) > 0xFFFF)
    return weird > len(sample) * 0.05  # More than 5% weird chars

def split_code(content: str, max_chars: int = 12000) -> list:
    """Split large code files into chunks by function/class boundaries"""
    if len(content) <= max_chars:
        return [content]
    
    # Find function/class markers
    markers = r"(?:^|\n)(?:def\s+|class\s+|function\s+|public\s+function\s+|private\s+function\s+)"
    parts = re.split(markers, content)
    
    chunks, buf = [], ""
    for p in parts:
        if not p.strip():
            continue
        # Reconstruct marker if needed
        candidate = p
        if not p.lstrip().startswith(("def ", "class ", "function", "public function", "private function")):
            # Check if previous part had a marker
            if "def " in content:
                candidate = "def " + p
            elif "class " in content:
                candidate = "class " + p
        
        if len(buf) + len(candidate) < max_chars:
            buf += candidate
        else:
            if buf:
                chunks.append(buf)
            buf = candidate
    
    if buf:
        chunks.append(buf)
    
    return chunks if chunks else [content]

def issue_key(issue: dict) -> str:
    """Generate a unique key for an issue to deduplicate"""
    base = f"{issue.get('type', '')}|{issue.get('description', '')}|{issue.get('line_hint', '')}"
    return hashlib.md5(base.encode()).hexdigest()

def scan_file_chunk(file_path, content_chunk, config, chunk_context="", max_retries=3, retry_delay=2):
    """Send a code chunk to LLM for analysis with improved prompt and JSON extraction"""
    # Improved prompt with checklist structure for Q4 models
    prompt = f"""You are a static analysis assistant. Output ONLY valid JSON.

Schema:
{{
  "issues": [
    {{
      "type": "security" | "pattern" | "regression",
      "severity": "high" | "medium" | "low",
      "description": "Specific, actionable problem statement",
      "line_hint": "One short code line or 'L<start>-L<end>' range",
      "cwe": "CWE-### if security, else ''"
    }}
  ]
}}

Analyze File: {file_path}

Checklist (answer by emitting issues that match):
1) Security: input validation, auth/authz gaps, unsafe deserialization, SQL/ORM injection, path traversal, SSRF, shell/exec misuse, secrets in code, weak crypto, insecure TLS.
2) Regressions: dead flags, removal of essential checks, brittle mocks, changes in error handling that swallow exceptions.
3) Legacy patterns: deprecated APIs, Python2 remnants, outdated PHP/React idioms, synchronous IO in async paths, global mutable state, tight coupling.

Rules:
- If unsure, omit the issue (prefer precision).
- Prefer 0–5 issues; no filler.
- Use **one line** or a small **line range** in line_hint.
- If no issues, return {{"issues":[]}} exactly.

Code:
{chunk_context}
{content_chunk}
"""
    
    # Get model config with defaults
    temperature = config['model'].get('temperature', 0.1)
    max_tokens = config['model'].get('max_tokens', 1024)
    top_p = config['model'].get('top_p', 0.2)
    
    for attempt in range(max_retries):
        try:
            # Build request params
            request_params = {
                "model": config['model']['name'],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens,
                "timeout": 60.0
            }
            
            # Add top_p if available
            if top_p is not None:
                request_params["top_p"] = top_p
            
            response = client.chat.completions.create(**request_params)
            
            result = response.choices[0].message.content
            candidate = extract_json_block(result) or result
            parsed = try_parse_json(candidate)
            
            # Self-repair if JSON parsing failed
            if not parsed:
                log_progress(f"⚠️  JSON parse failed for {file_path}, attempting self-repair...")
                try:
                    repair = client.chat.completions.create(
                        model=config['model']['name'],
                        messages=[
                            {"role": "system", "content": "Return ONLY valid minified JSON. No code fences. No commentary."},
                            {"role": "user", "content": f"Fix this to valid JSON matching schema {{'issues':[{{'type':'security|pattern|regression','severity':'high|medium|low','description':'','line_hint':'','cwe':''}}]}}:\n{candidate[:6000]}"}
                        ],
                        temperature=0.0,
                        max_tokens=512,
                        timeout=30.0
                    )
                    repaired = extract_json_block(repair.choices[0].message.content) or repair.choices[0].message.content
                    parsed = try_parse_json(repaired)
                except Exception as repair_error:
                    log_progress(f"⚠️  Self-repair failed: {repair_error}")
            
            if not parsed:
                log_progress(f"⚠️  JSON decode error for {file_path}: model returned non-JSON.")
                return {"issues": [], "error": "json_decode_error", "error_message": "Model returned non-JSON"}
            
            return parsed
            
        except APIConnectionError as e:
            # Connection errors - retry with backoff
            if attempt < max_retries - 1:
                wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
                log_progress(f"Connection error for {file_path} (attempt {attempt + 1}/{max_retries}). Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                log_progress(f"❌ Connection error for {file_path} after {max_retries} attempts: {e}")
                return {"issues": [], "error": "connection_failed", "error_message": str(e)}
                
        except APITimeoutError as e:
            # Timeout errors - retry
            if attempt < max_retries - 1:
                wait_time = retry_delay * (2 ** attempt)
                log_progress(f"Timeout error for {file_path} (attempt {attempt + 1}/{max_retries}). Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                log_progress(f"❌ Timeout error for {file_path} after {max_retries} attempts: {e}")
                return {"issues": [], "error": "timeout", "error_message": str(e)}
                
        except APIError as e:
            # Check for rate limits (429) or server busy (503)
            error_str = str(e)
            if '429' in error_str or '503' in error_str:
                if attempt < max_retries - 1:
                    wait_time = retry_delay * (2 ** attempt)
                    log_progress(f"Rate limit/server busy for {file_path}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue
            # Other API errors - log and return empty
            log_progress(f"❌ API error for {file_path}: {e}")
            return {"issues": [], "error": "api_error", "error_message": str(e)}
            
        except Exception as e:
            # Unexpected errors - log and return empty
            log_progress(f"❌ Unexpected error analyzing {file_path}: {type(e).__name__}: {e}")
            return {"issues": [], "error": "unknown_error", "error_message": str(e)}
    
    # Should never reach here, but just in case
    return {"issues": []}

def scan_file(file_path, content, config, max_retries=3, retry_delay=2):
    """Scan a file, handling chunking for large files"""
    # Extract file header/imports for context
    lines = content.split('\n')
    header_lines = []
    for line in lines[:50]:  # First 50 lines typically have imports/header
        if any(keyword in line for keyword in ['import', 'require', 'include', 'use', 'from', '#include', 'package']):
            header_lines.append(line)
    chunk_context = '\n'.join(header_lines) + '\n\n---\n\n' if header_lines else ''
    
    # Check if file needs chunking
    chunks = split_code(content, max_chars=12000)
    
    if len(chunks) == 1:
        # Single chunk - simple case
        return scan_file_chunk(file_path, content, config, chunk_context, max_retries, retry_delay)
    
    # Multiple chunks - process each and merge
    log_progress(f"📦 Chunking {file_path} into {len(chunks)} parts")
    all_issues = []
    seen_keys = set()
    
    for i, chunk in enumerate(chunks):
        chunk_result = scan_file_chunk(
            f"{file_path} (chunk {i+1}/{len(chunks)})",
            chunk,
            config,
            chunk_context,
            max_retries,
            retry_delay
        )
        
        # Deduplicate issues
        for issue in chunk_result.get('issues', []):
            key = issue_key(issue)
            if key not in seen_keys:
                seen_keys.add(key)
                all_issues.append(issue)
    
    return {"issues": all_issues}

def should_resume_from_folder(folder_path, state):
    """Determine if we should skip this folder (already completed)"""
    if state['last_scanned_folder'] is None:
        return True  # First run, start from beginning
    
    if folder_path in state['completed_folders']:
        return False  # Already completed this folder
    
    # If this is the folder we were working on, resume from it
    if state['last_scanned_folder'] and folder_path == state['last_scanned_folder']:
        return True
    
    # If we haven't reached our last position yet, skip
    if state['last_scanned_folder'] and folder_path < state['last_scanned_folder']:
        return False
    
    return True

def should_resume_from_file(file_path, state):
    """Determine if we should skip this file (already scanned in interrupted run)"""
    if state['last_scanned_file'] is None:
        return True
    
    # If we're past the last file we scanned, process this one
    if file_path > state['last_scanned_file']:
        return True
    
    return False

def scan_repos(config):
    """Walk through all repos and scan relevant files"""
    root_dir = config['scan']['root_directory']
    state = load_state()
    findings_db = load_findings()
    
    # Initialize scan start time if first run
    if state['scan_start_time'] is None:
        state['scan_start_time'] = datetime.now().isoformat()
        save_state(state)
    
    log_progress(f"Starting scan from root: {root_dir}")
    if state['last_scanned_folder']:
        log_progress(f"Resuming from folder: {state['last_scanned_folder']}")
        log_progress(f"Previous progress: {state['total_files_scanned']} files scanned, {state['total_files_skipped']} skipped")
    
    extensions = set(config['scan']['extensions'])
    exclude_dirs = set(config['scan']['exclude_dirs'])
    
    scanned_this_session = 0
    skipped_this_session = 0
    save_interval = config['scan']['save_interval']
    
    try:
        for root, dirs, files in os.walk(root_dir):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            dirs.sort()  # Sort for consistent ordering
            
            # Check if we should skip this folder
            if not should_resume_from_folder(root, state):
                log_progress(f"Skipping completed folder: {root}")
                continue
            
            log_progress(f"Processing folder: {root}")
            state['last_scanned_folder'] = root
            
            # Sort files for consistent ordering
            files.sort()
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip minified/bundled files
                if file.endswith(('.min.js', '.min.css', '.map', '.bundle.js')):
                    continue
                
                if Path(file_path).suffix not in extensions:
                    continue
                
                # Check if we should resume from this file
                if state['last_scanned_folder'] == root and not should_resume_from_file(file_path, state):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Skip binary files
                    if looks_binary(content):
                        log_progress(f"⚠️  Skipping binary file: {file_path}")
                        skipped_this_session += 1
                        state['total_files_skipped'] += 1
                        continue
                    
                    # Skip if already scanned this exact content
                    if not should_scan(file_path, content, findings_db):
                        skipped_this_session += 1
                        state['total_files_skipped'] += 1
                        continue
                    
                    log_progress(f"Scanning: {file_path}")
                    analysis = scan_file(file_path, content, config)
                    
                    # Store model metadata
                    model_meta = {
                        'model_name': config['model']['name'],
                        'temperature': config['model'].get('temperature', 0.1),
                        'max_tokens': config['model'].get('max_tokens', 1024),
                        'top_p': config['model'].get('top_p', 0.2)
                    }
                    
                    findings_db[file_path] = {
                        'hash': get_file_hash(content),
                        'scanned_at': datetime.now().isoformat(),
                        'file_size': len(content),
                        'findings': analysis.get('issues', []),
                        'model_meta': model_meta
                    }
                    
                    # Track errors if any
                    if 'error' in analysis:
                        findings_db[file_path]['scan_error'] = {
                            'type': analysis.get('error'),
                            'message': analysis.get('error_message', '')
                        }
                    
                    scanned_this_session += 1
                    state['total_files_scanned'] += 1
                    state['last_scanned_file'] = file_path
                    
                    # Periodic save
                    if scanned_this_session % save_interval == 0:
                        save_findings(findings_db)
                        save_state(state)
                        log_progress(f"Progress checkpoint: {state['total_files_scanned']} total files scanned")
                    
                except Exception as e:
                    log_progress(f"Skipped {file_path}: {e}")
            
            # Mark folder as completed
            state['completed_folders'].append(root)
            save_state(state)
            log_progress(f"Completed folder: {root}")
    
    except KeyboardInterrupt:
        log_progress("\n⚠️  Scan interrupted by user")
        save_findings(findings_db)
        save_state(state)
        log_progress(f"State saved. Resume anytime by running the script again.")
        log_progress(f"Session stats: {scanned_this_session} scanned, {skipped_this_session} skipped")
        return findings_db
    
    # Scan completed successfully
    state['last_run'] = datetime.now().isoformat()
    save_findings(findings_db)
    save_state(state)
    
    log_progress(f"\n✅ Scan completed!")
    log_progress(f"Total files scanned: {state['total_files_scanned']}")
    log_progress(f"Total files skipped: {state['total_files_skipped']}")
    log_progress(f"Session stats: {scanned_this_session} scanned, {skipped_this_session} skipped")
    
    return findings_db

def generate_report(findings_db):
    """Create a comprehensive, readable report"""
    # Organize issues by severity
    high_priority = []
    medium_priority = []
    low_priority = []
    
    # Also organize by file for file-by-file view
    files_with_issues = {}
    files_clean = []
    files_with_errors = []
    
    total_issues = 0
    seen_issue_keys = set()  # Global deduplication across files
    
    for file_path, data in findings_db.items():
        # Check for scan errors
        if 'scan_error' in data:
            files_with_errors.append({
                'file': file_path,
                'error_type': data['scan_error'].get('type', 'unknown'),
                'error_message': data['scan_error'].get('message', ''),
                'scanned_at': data.get('scanned_at', 'unknown')
            })
        
        findings = data.get('findings', [])
        if not findings:
            files_clean.append(file_path)
            continue
        
        files_with_issues[file_path] = {
            'findings': findings,
            'scanned_at': data.get('scanned_at', 'unknown'),
            'file_size': data.get('file_size', 0),
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
        
        # Deduplicate issues within file and across files
        for issue in findings:
            issue_key_hash = issue_key(issue)
            if issue_key_hash in seen_issue_keys:
                continue  # Skip duplicate
            seen_issue_keys.add(issue_key_hash)
            
            issue_copy = issue.copy()
            issue_copy['file'] = file_path
            issue_copy['scanned_at'] = data.get('scanned_at', 'unknown')
            total_issues += 1
            
            if issue['severity'] == 'high':
                high_priority.append(issue_copy)
                files_with_issues[file_path]['high_count'] += 1
            elif issue['severity'] == 'medium':
                medium_priority.append(issue_copy)
                files_with_issues[file_path]['medium_count'] += 1
            else:
                low_priority.append(issue_copy)
                files_with_issues[file_path]['low_count'] += 1
    
    # Generate report
    report = f"""# Code Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 📊 Executive Summary

| Metric | Count |
|--------|-------|
| **Total Files Analyzed** | {len(findings_db):,} |
| **Files with Issues** | {len(files_with_issues):,} |
| **Clean Files** | {len(files_clean):,} |
| **Total Issues Found** | {total_issues:,} |
| **🔴 High Priority** | {len(high_priority):,} |
| **🟡 Medium Priority** | {len(medium_priority):,} |
| **🟢 Low Priority** | {len(low_priority):,} |
| **⚠️ Files with Scan Errors** | {len(files_with_errors):,} |

**Issue Rate:** {(len(files_with_issues) / len(findings_db) * 100) if len(findings_db) > 0 else 0:.1f}% of files have issues

---

## 🔴 High Priority Issues ({len(high_priority)})

"""
    
    if high_priority:
        # Group by file for better readability
        issues_by_file = {}
        for issue in high_priority:
            file_path = issue['file']
            if file_path not in issues_by_file:
                issues_by_file[file_path] = []
            issues_by_file[file_path].append(issue)
        
        for file_path, file_issues in sorted(issues_by_file.items()):
            report += f"\n### 📄 {file_path}\n\n"
            report += f"*Scanned: {file_issues[0]['scanned_at']} | {len(file_issues)} issue(s)*\n\n"
            
            for idx, issue in enumerate(file_issues, 1):
                report += f"#### Issue #{idx}: {issue.get('type', 'unknown').upper()}\n\n"
                if issue.get('cwe'):
                    report += f"**CWE:** {issue['cwe']}\n\n"
                report += f"{issue['description']}\n\n"
                if issue.get('line_hint'):
                    report += f"**Code Snippet:**\n```\n{issue['line_hint']}\n```\n\n"
                report += "---\n\n"
    else:
        report += "✅ **No high priority issues found!**\n\n"
    
    report += f"\n## 🟡 Medium Priority Issues ({len(medium_priority)})\n\n"
    
    if medium_priority:
        issues_by_file = {}
        for issue in medium_priority:
            file_path = issue['file']
            if file_path not in issues_by_file:
                issues_by_file[file_path] = []
            issues_by_file[file_path].append(issue)
        
        for file_path, file_issues in sorted(issues_by_file.items()):
            report += f"\n### 📄 {file_path}\n\n"
            report += f"*{len(file_issues)} issue(s)*\n\n"
            
            for idx, issue in enumerate(file_issues, 1):
                cwe_str = f" [{issue['cwe']}]" if issue.get('cwe') else ""
                report += f"**{issue.get('type', 'unknown').upper()}{cwe_str}:** {issue['description']}\n"
                if issue.get('line_hint'):
                    report += f"\n```\n{issue['line_hint']}\n```\n"
                report += "\n"
    else:
        report += "✅ **No medium priority issues found!**\n\n"
    
    report += f"\n## 🟢 Low Priority Issues ({len(low_priority)})\n\n"
    
    if low_priority:
        # Group low priority by file for compactness
        issues_by_file = {}
        for issue in low_priority:
            file_path = issue['file']
            if file_path not in issues_by_file:
                issues_by_file[file_path] = []
            issues_by_file[file_path].append(issue)
        
        for file_path, file_issues in sorted(issues_by_file.items()):
            report += f"\n**{file_path}** ({len(file_issues)} issue(s)):\n"
            for issue in file_issues:
                report += f"- *{issue.get('type', 'unknown')}*: {issue['description']}\n"
            report += "\n"
    else:
        report += "✅ **No low priority issues found!**\n\n"
    
    # Add file-by-file summary
    report += f"\n---\n\n## 📁 Files with Issues (Summary)\n\n"
    report += "| File | High | Medium | Low | Total | Scanned At |\n"
    report += "|------|------|--------|-----|-------|------------|\n"
    
    for file_path, file_data in sorted(files_with_issues.items()):
        total = file_data['high_count'] + file_data['medium_count'] + file_data['low_count']
        scanned = file_data['scanned_at'].split('T')[0] if 'T' in file_data['scanned_at'] else file_data['scanned_at']
        report += f"| `{file_path}` | {file_data['high_count']} | {file_data['medium_count']} | {file_data['low_count']} | **{total}** | {scanned} |\n"
    
    # Add issue type breakdown
    issue_types = {}
    for file_path, data in findings_db.items():
        for issue in data.get('findings', []):
            issue_type = issue.get('type', 'unknown')
            if issue_type not in issue_types:
                issue_types[issue_type] = {'high': 0, 'medium': 0, 'low': 0}
            issue_types[issue_type][issue['severity']] += 1
    
    if issue_types:
        report += f"\n---\n\n## 📈 Issue Type Breakdown\n\n"
        report += "| Type | High | Medium | Low | Total |\n"
        report += "|------|------|--------|-----|-------|\n"
        for issue_type, counts in sorted(issue_types.items()):
            total = counts['high'] + counts['medium'] + counts['low']
            report += f"| {issue_type} | {counts['high']} | {counts['medium']} | {counts['low']} | **{total}** |\n"
    
    # Add section for files with scan errors
    if files_with_errors:
        report += f"\n---\n\n## ⚠️ Files with Scan Errors ({len(files_with_errors)})\n\n"
        report += "These files encountered errors during scanning and may need to be rescanned:\n\n"
        report += "| File | Error Type | Error Message | Scanned At |\n"
        report += "|------|------------|---------------|------------|\n"
        for error_info in files_with_errors:
            file_path = error_info['file']
            error_type = error_info['error_type']
            error_msg = error_info['error_message'][:100] + "..." if len(error_info['error_message']) > 100 else error_info['error_message']
            scanned = error_info['scanned_at'].split('T')[0] if 'T' in error_info['scanned_at'] else error_info['scanned_at']
            report += f"| `{file_path}` | {error_type} | {error_msg} | {scanned} |\n"
        report += f"\n💡 **Tip:** Files with connection errors can be rescanned by deleting their entry from `code_analysis_findings.json` or running the scanner again (it will skip unchanged files).\n\n"
    
    with open('code_analysis_report.md', 'w') as f:
        f.write(report)
    
    log_progress(f"\n✅ Report saved to code_analysis_report.md")
    log_progress(f"   Summary: {len(high_priority)} high, {len(medium_priority)} medium, {len(low_priority)} low priority issues")

def show_status():
    """Show current scan status"""
    state = load_state()
    
    if state['last_scanned_folder'] is None:
        print("No scan in progress. Run scan to start.")
        return
    
    print(f"\n📊 Scan Status")
    print(f"─" * 50)
    print(f"Started: {state.get('scan_start_time', 'unknown')}")
    print(f"Last folder: {state['last_scanned_folder']}")
    print(f"Last file: {state['last_scanned_file']}")
    print(f"Completed folders: {len(state['completed_folders'])}")
    print(f"Files scanned: {state['total_files_scanned']}")
    print(f"Files skipped: {state['total_files_skipped']}")
    
    if state['last_run']:
        print(f"Last completed: {state['last_run']}")
    else:
        print("Status: IN PROGRESS (can resume)")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        show_status()
    elif len(sys.argv) > 1 and sys.argv[1] == "report":
        findings = load_findings()
        generate_report(findings)
    else:
        print("Starting scan... (Press Ctrl+C to pause and resume later)")
        findings = scan_repos(config)
        generate_report(findings)
