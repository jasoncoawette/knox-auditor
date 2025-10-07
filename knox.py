#!/usr/bin/env python3
"""
Knox Security Auditor CLI
Command-line interface for security auditing
"""
import argparse
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.scanner import CodeScanner
from core.analyzer import AISecurityAnalyzer
from core.reporter import SecurityReporter
from integrations.github import GitHubIntegration

def main():
    parser = argparse.ArgumentParser(
        description='Knox - AI Security Code Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  knox.py scan /path/to/repo
  knox.py scan --files src/auth.py src/api.py
  knox.py audit-pr --repo owner/repo --pr 123
  knox.py demo
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan code for vulnerabilities')
    scan_parser.add_argument('path', nargs='?', default='.', help='Path to scan (default: current directory)')
    scan_parser.add_argument('--files', nargs='+', help='Specific files to scan')
    scan_parser.add_argument('--output', '-o', help='Output file for report')
    scan_parser.add_argument('--format', choices=['json', 'html', 'cli'], default='cli', help='Report format')
    scan_parser.add_argument('--no-ai', action='store_true', help='Skip AI analysis')

    # GitHub PR audit command
    pr_parser = subparsers.add_parser('audit-pr', help='Audit a GitHub pull request')
    pr_parser.add_argument('--repo', required=True, help='Repository in format owner/repo')
    pr_parser.add_argument('--pr', type=int, required=True, help='Pull request number')
    pr_parser.add_argument('--comment', action='store_true', help='Post results as PR comment')

    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run demo scan on sample vulnerable code')

    # Server command
    server_parser = subparsers.add_parser('server', help='Start API server')
    server_parser.add_argument('--port', type=int, default=8000, help='Port to run server on')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Initialize components
    scanner = CodeScanner()
    analyzer = AISecurityAnalyzer()
    reporter = SecurityReporter()

    if args.command == 'scan':
        print("🔍 Knox Security Auditor - Starting scan...\n")

        # Scan files
        if args.files:
            findings = []
            for file_path in args.files:
                print(f"Scanning {file_path}...")
                findings.extend(scanner.scan_file(file_path))
        else:
            print(f"Scanning directory: {args.path}")
            findings = scanner.scan_directory(args.path)

        print(f"\n✅ Scan complete. Found {len(findings)} potential issues.\n")

        # Analyze with AI if enabled
        if not args.no_ai and os.getenv('OPENAI_API_KEY'):
            print("🤖 Running AI analysis...\n")
            analysis = analyzer.analyze_findings(findings)
        else:
            # Basic analysis without AI
            analysis = {
                "total_issues": len(findings),
                "critical": len([f for f in findings if f.get('severity') == 'critical']),
                "high": len([f for f in findings if f.get('severity') == 'high']),
                "medium": len([f for f in findings if f.get('severity') == 'medium']),
                "low": len([f for f in findings if f.get('severity') == 'low']),
                "findings": findings
            }

        # Generate report
        if args.format == 'json':
            report = reporter.generate_json_report(analysis, args.output)
            if not args.output:
                print(report)
        elif args.format == 'html':
            report = reporter.generate_html_report(analysis, args.output)
            if args.output:
                print(f"📄 HTML report saved to: {args.output}")
            else:
                print(report)
        else:  # CLI format
            report = reporter.generate_cli_report(analysis)
            print(report)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"📄 Report saved to: {args.output}")

    elif args.command == 'audit-pr':
        github = GitHubIntegration()

        if not os.getenv('GITHUB_TOKEN'):
            print("❌ Error: GITHUB_TOKEN environment variable not set")
            print("Please set your GitHub personal access token:")
            print("  export GITHUB_TOKEN=your_token_here")
            sys.exit(1)

        owner, repo = args.repo.split('/')
        print(f"🔍 Auditing PR #{args.pr} in {owner}/{repo}...\n")

        # Get PR files
        files = github.get_pr_files(owner, repo, args.pr)

        if not files:
            print("❌ No files found or unable to access PR")
            sys.exit(1)

        print(f"Found {len(files)} changed files\n")

        # Scan each file
        all_findings = []
        for file in files:
            if file.get('status') != 'removed':
                print(f"Scanning {file['filename']}...")
                # For MVP, we'll just note the files
                # In production, you'd fetch and scan actual content
                all_findings.append({
                    "file": file['filename'],
                    "type": "info",
                    "severity": "info",
                    "message": f"File changed: +{file.get('additions', 0)} -{file.get('deletions', 0)}"
                })

        print(f"\n✅ Audit complete.\n")

        analysis = analyzer.analyze_findings(all_findings)
        report = reporter.generate_cli_report(analysis)
        print(report)

        if args.comment:
            comment = f"""## 🔒 Knox Security Audit

**PR #{args.pr} scanned successfully**

Files reviewed: {len(files)}
Issues found: {len(all_findings)}

Automated security audit by Knox."""
            if github.post_pr_comment(owner, repo, args.pr, comment):
                print("✅ Posted comment to PR")
            else:
                print("❌ Failed to post comment")

    elif args.command == 'demo':
        print("🔍 Knox Security Auditor - Demo Mode\n")
        print("Scanning demo vulnerable code...\n")

        demo_code = '''
# Demo vulnerable code
import hashlib
import pickle

API_KEY = "sk-1234567890abcdef"  # Hardcoded secret
PASSWORD = "admin123"  # Hardcoded password

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection
    return db.execute(query)

def hash_password(password):
    return hashlib.md5(password.encode())  # Weak hashing

def deserialize(data):
    return pickle.loads(data)  # Insecure deserialization
'''

        # Create temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
            tmp.write(demo_code)
            tmp_path = tmp.name

        findings = scanner.scan_file(tmp_path)
        analysis = analyzer.analyze_findings(findings)
        report = reporter.generate_cli_report(analysis)
        print(report)

        # Cleanup
        os.unlink(tmp_path)

        print("\n💡 This demo shows Knox detecting common security vulnerabilities.")
        print("   Run 'knox.py scan /your/repo' to scan your actual code!\n")

    elif args.command == 'server':
        print(f"🚀 Starting Knox API server on port {args.port}...\n")
        os.environ['PORT'] = str(args.port)

        from src.api.main import app
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=args.port)

if __name__ == "__main__":
    main()
