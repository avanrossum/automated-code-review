import os
import json
from pathlib import Path
from openai import OpenAI
import hashlib
from datetime import datetime
import time
import sys

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

def scan_file(file_path, content, config):
    """Send file to LLM for analysis"""
    prompt = f"""Analyze this code for issues. Return ONLY valid JSON in this format:
{{
  "issues": [
    {{
      "type": "security|pattern|regression",
      "severity": "high|medium|low",
      "description": "what's wrong",
      "line_hint": "relevant code snippet if applicable"
    }}
  ]
}}

File: {file_path}

```
{content}
```

If no issues found, return {{"issues": []}}
"""
    
    try:
        response = client.chat.completions.create(
            model=config['model']['name'],
            messages=[{"role": "user", "content": prompt}],
            temperature=config['model']['temperature'],
            max_tokens=config['model']['max_tokens']
        )
        
        result = response.choices[0].message.content
        # Try to extract JSON if model wrapped it in markdown
        if "```json" in result:
            result = result.split("```json")[1].split("```")[0]
        elif "```" in result:
            result = result.split("```")[1].split("```")[0]
        
        return json.loads(result.strip())
    except json.JSONDecodeError as e:
        log_progress(f"JSON decode error for {file_path}: {e}")
        return {"issues": []}
    except Exception as e:
        log_progress(f"Error analyzing {file_path}: {e}")
        return {"issues": []}

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
                
                if Path(file_path).suffix not in extensions:
                    continue
                
                # Check if we should resume from this file
                if state['last_scanned_folder'] == root and not should_resume_from_file(file_path, state):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Skip if already scanned this exact content
                    if not should_scan(file_path, content, findings_db):
                        skipped_this_session += 1
                        state['total_files_skipped'] += 1
                        continue
                    
                    log_progress(f"Scanning: {file_path}")
                    analysis = scan_file(file_path, content, config)
                    
                    findings_db[file_path] = {
                        'hash': get_file_hash(content),
                        'scanned_at': datetime.now().isoformat(),
                        'file_size': len(content),
                        'findings': analysis.get('issues', [])
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
    
    total_issues = 0
    for file_path, data in findings_db.items():
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
        
        for issue in findings:
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
                report += f"**{issue.get('type', 'unknown').upper()}:** {issue['description']}\n"
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
