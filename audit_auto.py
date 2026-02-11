#!/usr/bin/env python3
"""
Linux Audit System Automation Tool
Manages and investigates audit rules, generates reports, and handles incident response
"""

import os
import sys
import subprocess
import argparse
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
import time
import signal
from typing import List, Dict, Optional, Tuple
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import csv

# Configuration
AUDIT_LOG = "/var/log/audit/audit.log"
RULES_FILE = "/etc/audit/rules.d/hardening.rules"
DEFAULT_TIME = "today"
ALERT_EMAIL = "admin@localhost"
REPORT_DIR = "/var/log/audit/reports"

class AuditManager:
    def __init__(self):
        self.ensure_directories()
        
    def ensure_directories(self):
        """Create necessary directories for reports"""
        os.makedirs(REPORT_DIR, exist_ok=True)
        os.makedirs(f"{REPORT_DIR}/alerts", exist_ok=True)
        os.makedirs(f"{REPORT_DIR}/exports", exist_ok=True)
        
    def run_command(self, cmd: List[str]) -> Tuple[str, str, int]:
        """Run shell command with sudo"""
        if not cmd[0] == 'sudo':
            cmd.insert(0, 'sudo')
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return result.stdout, result.stderr, result.returncode
        except Exception as e:
            return "", str(e), 1

    # ============= STATUS & MANAGEMENT =============
    
    def check_status(self):
        """Check audit system status"""
        print("\n=== AUDIT SYSTEM STATUS ===\n")
        
        # Check if auditd is running
        stdout, _, rc = self.run_command(['systemctl', 'is-active', 'auditd'])
        status = "✅ Running" if rc == 0 else "❌ Not Running"
        print(f"Auditd Service: {status}")
        
        # Check rules count
        stdout, _, _ = self.run_command(['auditctl', '-l'])
        rules_count = len(stdout.strip().split('\n')) if stdout.strip() else 0
        print(f"Active Rules: {rules_count}")
        
        # Check disk space
        stdout, _, _ = self.run_command(['df', '-h', '/var/log/audit/'])
        if stdout:
            usage = stdout.split('\n')[1].split()[4]
            print(f"Disk Usage: {usage}")
            
        # Check log file size
        if os.path.exists(AUDIT_LOG):
            size = os.path.getsize(AUDIT_LOG) / (1024*1024)
            print(f"Log Size: {size:.1f} MB")
            
        # Last events
        stdout, _, _ = self.run_command(['ausearch', '-ts', 'recent', '-r'])
        if stdout:
            recent_count = len(stdout.strip().split('\n'))
            print(f"Events (last 5 min): {recent_count}")
            
        return status

    def apply_rules(self):
        """Deploy audit rules"""
        print("\n=== DEPLOYING AUDIT RULES ===\n")
        
        if not os.path.exists(RULES_FILE):
            print(f"❌ Rules file not found: {RULES_FILE}")
            return False
            
        # Restart auditd to apply rules
        stdout, stderr, rc = self.run_command(['systemctl', 'restart', 'auditd'])
        if rc == 0:
            print("✅ Rules applied successfully")
            self.check_status()
            return True
        else:
            print(f"❌ Failed to apply rules: {stderr}")
            return False

    # ============= SEARCH OPERATIONS =============
    
    def search(self, key: str = None, time_range: str = DEFAULT_TIME, 
               user: str = None, file_path: str = None, 
               syscall: str = None, output_format: str = 'text'):
        """Search audit events"""
        cmd = ['ausearch']
        
        if key:
            cmd.extend(['-k', key])
        if time_range:
            cmd.extend(['-ts', time_range])
        if user:
            if user.isdigit():
                cmd.extend(['-ui', user])
            else:
                cmd.extend(['-ua', user])
        if file_path:
            cmd.extend(['-f', file_path])
        if syscall:
            cmd.extend(['-m', syscall])
            
        if output_format == 'json':
            cmd.extend(['--format', 'json'])
        else:
            cmd.extend(['--format', 'text'])
            
        stdout, stderr, rc = self.run_command(cmd)
        
        if rc == 0 and stdout:
            if output_format == 'json':
                return self.parse_json_output(stdout)
            return stdout
        else:
            return "No events found"

    def search_by_key(self, key: str, time_range: str = DEFAULT_TIME):
        """Search by key with formatting"""
        print(f"\n=== EVENTS: {key} ({time_range}) ===\n")
        result = self.search(key=key, time_range=time_range)
        print(result[:2000] + "..." if len(result) > 2000 else result)
        return result

    # ============= REPORT GENERATION =============
    
    def generate_daily_report(self):
        """Generate comprehensive daily security report"""
        today = datetime.now().strftime("%Y-%m-%d")
        report_file = f"{REPORT_DIR}/daily-report-{today}.txt"
        
        report = []
        report.append("="*80)
        report.append(f"AUDIT SECURITY REPORT - {today}")
        report.append("="*80)
        
        sections = [
            ("Failed Logins", ['aureport', '-l', '--failed', '-ts', 'today']),
            ("Root Commands", ['ausearch', '-k', 'root_command', '-ts', 'today', '--format', 'text']),
            ("File Deletions", ['ausearch', '-k', 'file_deletion', '-ts', 'today', '--format', 'text']),
            ("Suspicious Tools", ['ausearch', '-k', 'lolbin', '-ts', 'today', '--format', 'text']),
            ("Permission Changes", ['ausearch', '-k', 'perm_mod', '-ts', 'today', '--format', 'text']),
            ("Cron Modifications", ['ausearch', '-k', 'cron', '-ts', 'today', '--format', 'text']),
            ("SSH Activity", ['ausearch', '-k', 'ssh_keys', '-k', 'ssh_config', '-ts', 'today', '--format', 'text']),
        ]
        
        for title, cmd in sections:
            report.append(f"\n▶️ {title}")
            report.append("-"*40)
            stdout, _, _ = self.run_command(cmd)
            if stdout.strip():
                # Limit output
                lines = stdout.strip().split('\n')
                report.extend(lines[:20])
                if len(lines) > 20:
                    report.append(f"... and {len(lines)-20} more entries")
            else:
                report.append("No events found")
        
        report_content = "\n".join(report)
        
        # Save report
        with open(report_file, 'w') as f:
            f.write(report_content)
            
        print(f"✅ Daily report saved: {report_file}")
        
        # Also save as JSON for parsing
        self.export_events('json', f"{REPORT_DIR}/exports/events-{today}.json")
        
        return report_content

    def generate_user_report(self, username: str, time_range: str = DEFAULT_TIME):
        """Generate detailed report for specific user"""
        print(f"\n=== USER ACTIVITY REPORT: {username} ({time_range}) ===\n")
        
        # Get UID
        stdout, _, rc = self.run_command(['id', '-u', username])
        if rc != 0:
            print(f"❌ User not found: {username}")
            return
            
        uid = stdout.strip()
        
        report = []
        report.append(f"\n1. Commands executed:")
        stdout, _, _ = self.run_command(['ausearch', '-ui', uid, '-k', 'process_execution', 
                                        '-ts', time_range, '--format', 'text'])
        report.append(stdout[:500] if len(stdout) > 500 else stdout)
        
        report.append(f"\n2. Files accessed:")
        stdout, _, _ = self.run_command(['ausearch', '-ui', uid, '-ts', time_range, 
                                        '--format', 'text'])
        # Filter for file access events
        file_events = [line for line in stdout.split('\n') if 'type=SYSCALL' in line]
        report.extend(file_events[:20])
        
        report.append(f"\n3. Sudo usage:")
        stdout, _, _ = self.run_command(['ausearch', '-ui', uid, '-k', 'privilege_escalation', 
                                        '-ts', time_range, '--format', 'text'])
        report.append(stdout[:500] if len(stdout) > 500 else stdout)
        
        print("\n".join(report))
        return "\n".join(report)

    # ============= INCIDENT RESPONSE =============
    
    def incident_response(self, scenario: str):
        """Run predefined incident response scenarios"""
        scenarios = {
            'ssh': self.incident_ssh,
            'backdoor': self.incident_backdoor,
            'privilege': self.incident_privilege_escalation,
            'exfiltration': self.incident_data_exfiltration,
            'all': self.incident_all
        }
        
        if scenario in scenarios:
            scenarios[scenario]()
        else:
            print(f"Unknown scenario: {scenario}")
            print("Available: ssh, backdoor, privilege, exfiltration, all")

    def incident_ssh(self):
        """Investigate suspicious SSH activity"""
        print("\n=== 🚨 INCIDENT RESPONSE: Suspicious SSH Activity ===\n")
        
        checks = [
            ("1. SSH Logins", ['aureport', '-l', '-ts', 'today']),
            ("2. SSH Key Modifications", ['ausearch', '-k', 'ssh_keys', '-ts', 'today']),
            ("3. SSH Config Changes", ['ausearch', '-k', 'ssh_config', '-ts', 'today']),
            ("4. Outbound Connections from SSH", ['ausearch', '-k', 'outbound_connection', '-ts', 'today']),
            ("5. Failed SSH Attempts", ['ausearch', '-k', 'failed_logins', '-ts', 'today']),
        ]
        
        for title, cmd in checks:
            print(f"\n{title}")
            print("-"*40)
            stdout, _, _ = self.run_command(cmd)
            if stdout.strip():
                print(stdout[:1000])
            else:
                print("No suspicious activity found")

    def incident_backdoor(self):
        """Investigate possible backdoor/reverse shell"""
        print("\n=== 🚨 INCIDENT RESPONSE: Possible Backdoor/Reverse Shell ===\n")
        
        checks = [
            ("1. LOLBin Execution", ['ausearch', '-k', 'lolbin', '-ts', 'today']),
            ("2. Outbound Connections", ['ausearch', '-k', 'outbound_connection', '-ts', 'today']),
            ("3. Suspicious Listening Ports", ['ausearch', '-k', 'socket_bind', '-ts', 'today']),
            ("4. Cron Modifications", ['ausearch', '-k', 'cron', '-ts', 'today']),
            ("5. New Systemd Services", ['ausearch', '-k', 'systemd', '-ts', 'today']),
            ("6. Web Shells", ['ausearch', '-k', 'web_content', '-ts', 'today']),
        ]
        
        for title, cmd in checks:
            print(f"\n{title}")
            print("-"*40)
            stdout, _, _ = self.run_command(cmd)
            if stdout.strip():
                print(stdout[:1000])
            else:
                print("No suspicious activity found")

    def incident_privilege_escalation(self):
        """Investigate privilege escalation attempts"""
        print("\n=== 🚨 INCIDENT RESPONSE: Privilege Escalation Attempt ===\n")
        
        checks = [
            ("1. Sudo Usage", ['ausearch', '-k', 'privilege_escalation', '-ts', 'today']),
            ("2. SUID Binary Execution", ['ausearch', '-k', 'suid_change', '-ts', 'today']),
            ("3. Failed Root Attempts", ['ausearch', '-m', 'execve', '-ui', '0', '-sv', 'no', '-ts', 'today']),
            ("4. Chmod 777", ['ausearch', '-k', 'chmod_777', '-ts', 'today']),
            ("5. PKexec Usage", ['ausearch', '-k', 'pkexec', '-ts', 'today']),
        ]
        
        for title, cmd in checks:
            print(f"\n{title}")
            print("-"*40)
            stdout, _, _ = self.run_command(cmd)
            if stdout.strip():
                print(stdout[:1000])
            else:
                print("No suspicious activity found")

    def incident_data_exfiltration(self):
        """Investigate possible data exfiltration"""
        print("\n=== 🚨 INCIDENT RESPONSE: Data Exfiltration ===\n")
        
        checks = [
            ("1. Large File Reads", ['ausearch', '-k', 'web_content', '-ts', 'today']),
            ("2. Outbound Connections", ['ausearch', '-k', 'outbound_connection', '-ts', 'today']),
            ("3. USB Mounts", ['ausearch', '-k', 'usb_mount', '-ts', 'today']),
            ("4. Compression Tools", ['ausearch', '-k', 'lolbin', '-ts', 'today']),
        ]
        
        for title, cmd in checks:
            print(f"\n{title}")
            print("-"*40)
            stdout, _, _ = self.run_command(cmd)
            if stdout.strip():
                # Filter for relevant file extensions
                if 'large' in title:
                    lines = [l for l in stdout.split('\n') 
                           if any(ext in l.lower() for ext in ['.sql', '.tar', '.gz', '.zip', '.db'])]
                    print("\n".join(lines[:20]))
                else:
                    print(stdout[:500])
            else:
                print("No suspicious activity found")

    def incident_all(self):
        """Run all incident response scenarios"""
        self.incident_ssh()
        self.incident_backdoor()
        self.incident_privilege_escalation()
        self.incident_data_exfiltration()

    # ============= MONITORING & ALERTS =============
    
    def live_monitor(self, patterns: List[str] = None):
        """Real-time monitoring of audit log"""
        if not patterns:
            patterns = ["FAILED", "DENIED", "chmod 777", "root", "sudo", "SUID", "C2"]
            
        print(f"\n=== LIVE MONITORING (patterns: {', '.join(patterns)}) ===\n")
        print("Press Ctrl+C to stop\n")
        
        try:
            cmd = ['sudo', 'tail', '-f', AUDIT_LOG]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            grep_pattern = '|'.join(patterns)
            
            for line in iter(process.stdout.readline, ''):
                if any(pattern.lower() in line.lower() for pattern in patterns):
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"[{timestamp}] 🚨 ALERT: {line.strip()}")
                    
        except KeyboardInterrupt:
            print("\n\n✅ Monitoring stopped")
            process.terminate()

    def check_alerts(self):
        """Check for security alerts"""
        print("\n=== SECURITY ALERTS ===\n")
        
        alerts = []
        
        # Check root commands
        stdout, _, rc = self.run_command(['ausearch', '-k', 'root_command', '-ts', 'recent', '-r'])
        if rc == 0 and stdout:
            count = len(stdout.strip().split('\n'))
            alerts.append(f"⚠️  {count} root commands executed (last 5 min)")
            
        # Check LOLBin usage
        stdout, _, rc = self.run_command(['ausearch', '-k', 'lolbin', '-ts', 'recent', '-r'])
        if rc == 0 and stdout:
            count = len(stdout.strip().split('\n'))
            alerts.append(f"⚠️  {count} suspicious tool executions (last 5 min)")
            
        # Check failed logins
        stdout, _, rc = self.run_command(['aureport', '-l', '--failed', '-ts', 'recent', '--summary'])
        if rc == 0 and stdout:
            lines = stdout.strip().split('\n')
            if len(lines) > 3:
                count = len(lines) - 3
                if count > 5:
                    alerts.append(f"🚨 {count} failed logins (last 5 min) - Possible brute force!")
                elif count > 0:
                    alerts.append(f"⚠️  {count} failed logins (last 5 min)")
                    
        # Check privilege escalation
        stdout, _, rc = self.run_command(['ausearch', '-k', 'privilege_escalation', '-ts', 'recent', '-r'])
        if rc == 0 and stdout:
            count = len(stdout.strip().split('\n'))
            alerts.append(f"⚠️  {count} privilege escalations (last 5 min)")
            
        if alerts:
            for alert in alerts:
                print(alert)
                
            # Save alerts
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            with open(f"{REPORT_DIR}/alerts/alerts-{timestamp}.txt", 'w') as f:
                f.write("\n".join(alerts))
        else:
            print("✅ No security alerts detected")

    def send_email_alert(self, subject: str, body: str, recipient: str = ALERT_EMAIL):
        """Send email alerts (configurable)"""
        # This is a placeholder - configure with your email settings
        print(f"\n📧 Email alert would be sent to {recipient}")
        print(f"Subject: {subject}")
        print(f"Body:\n{body}")

    # ============= FORENSICS & EXPORT =============
    
    def export_events(self, format_type: str = 'json', output_file: str = None):
        """Export events for forensic analysis"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{REPORT_DIR}/exports/audit-export-{timestamp}.{format_type}"
            
        if format_type == 'json':
            stdout, _, _ = self.run_command(['ausearch', '-ts', 'today', '--format', 'json'])
            if stdout:
                with open(output_file, 'w') as f:
                    f.write(stdout)
                print(f"✅ Events exported to {output_file}")
                
        elif format_type == 'csv':
            # Parse ausearch output and create CSV
            stdout, _, _ = self.run_command(['ausearch', '-ts', 'today', '--format', 'text'])
            if stdout:
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Type', 'Event', 'User', 'Process', 'Key'])
                    
                    for line in stdout.split('\n'):
                        if 'type=SYSCALL' in line:
                            # Parse relevant fields
                            timestamp = re.search(r'msg=audit\((\d+)', line)
                            event_type = re.search(r'type=(\w+)', line)
                            user = re.search(r'uid=(\w+)', line)
                            process = re.search(r'proctitle=(\w+)', line)
                            key = re.search(r'key="([^"]+)"', line)
                            
                            writer.writerow([
                                timestamp.group(1) if timestamp else '',
                                event_type.group(1) if event_type else '',
                                line[:100],
                                user.group(1) if user else '',
                                process.group(1) if process else '',
                                key.group(1) if key else ''
                            ])
                print(f"✅ Events exported to {output_file}")
                
        elif format_type == 'text':
            stdout, _, _ = self.run_command(['ausearch', '-ts', 'today', '--format', 'text'])
            if stdout:
                with open(output_file, 'w') as f:
                    f.write(stdout)
                print(f"✅ Events exported to {output_file}")

    def investigate_file(self, filepath: str, time_range: str = DEFAULT_TIME):
        """Track everything related to a specific file"""
        print(f"\n=== FILE INVESTIGATION: {filepath} ({time_range}) ===\n")
        
        checks = [
            ("File Access Events", ['ausearch', '-f', filepath, '-ts', time_range]),
            ("Detailed Activity", ['ausearch', '-f', filepath, '-ts', time_range, '--format', 'text']),
            ("Summary Report", ['aureport', '-f', '-ts', time_range, '|', 'grep', filepath]),
        ]
        
        for title, cmd in checks:
            print(f"\n{title}:")
            print("-"*40)
            stdout, _, _ = self.run_command(cmd)
            if stdout.strip():
                print(stdout[:500])
            else:
                print("No activity found")

    def investigate_time_range(self, start_time: str, end_time: str = None):
        """Investigate activity during specific time range"""
        if not end_time:
            end_time = datetime.now().strftime("%H:%M")
            
        print(f"\n=== TIME RANGE INVESTIGATION: {start_time} to {end_time} ===\n")
        
        cmd = ['ausearch', '-ts', start_time, '-te', end_time]
        stdout, _, _ = self.run_command(cmd)
        
        # Generate summary
        summary_cmd = ['aureport', '--summary', '-ts', start_time, '-te', end_time]
        stdout_summary, _, _ = self.run_command(summary_cmd)
        
        print("SUMMARY:")
        print(stdout_summary)
        
        print("\nTOP EVENTS:")
        print(stdout[:1000] if stdout else "No events found")

    # ============= QUICK WINS =============
    
    def quick_threat_hunt(self):
        """One-liner threat hunt - find suspicious activity"""
        print("\n=== 🎯 QUICK THREAT HUNT (Last 24h) ===\n")
        
        suspicious_keys = [
            'lolbin', 'privilege_escalation', 'kernel_module', 
            'file_deletion', 'outbound_connection', 'ssh_keys',
            'sudoers', 'cron', 'systemd', 'web_content'
        ]
        
        for key in suspicious_keys:
            stdout, _, rc = self.run_command(['ausearch', '-k', key, '-ts', 'today', '-r'])
            if rc == 0 and stdout:
                count = len(stdout.strip().split('\n'))
                print(f"⚠️  {key}: {count} events")

    def daily_digest(self):
        """Quick daily digest email"""
        summary, _, _ = self.run_command(['aureport', '--summary', '-ts', 'today'])
        return summary

    def morning_checklist(self):
        """Run morning security checklist"""
        print("\n=== 🌅 MORNING CHECKLIST ===\n")
        
        checks = [
            ("1. Audit Status", self.check_status),
            ("2. Disk Space", ['df', '-h', '/var/log/audit/']),
            ("3. Overnight Activity", ['aureport', '--summary', '-ts', 'yesterday']),
            ("4. Failed Logins", ['aureport', '-l', '--failed', '-ts', 'yesterday']),
            ("5. Root Activity", ['ausearch', '-k', 'root_command', '-ts', 'yesterday']),
            ("6. Critical File Changes", ['ausearch', '-k', 'identity', '-k', 'sudoers', 
                                         '-k', 'ssh_config', '-ts', 'yesterday']),
        ]
        
        for title, cmd in checks:
            print(f"\n{title}")
            print("-"*40)
            if callable(cmd):
                cmd()
            else:
                stdout, _, _ = self.run_command(cmd)
                if stdout.strip():
                    print(stdout[:500])
                else:
                    print("No activity found")

    def parse_json_output(self, json_str: str) -> Dict:
        """Parse JSON output from ausearch"""
        try:
            return json.loads(json_str)
        except:
            return {"error": "Failed to parse JSON"}

def main():
    parser = argparse.ArgumentParser(
        description='Linux Audit System Automation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s status                    # Check audit system status
  %(prog)s search -k ssh_keys        # Search SSH key events
  %(prog)s report daily              # Generate daily report
  %(prog)s incident ssh             # Investigate SSH incident
  %(prog)s monitor                  # Live monitoring
  %(prog)s export -f json           # Export events as JSON
        """
    )
    
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Status command
    subparsers.add_parser('status', help='Check audit system status')
    
    # Apply rules command
    subparsers.add_parser('apply', help='Apply audit rules')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search audit events')
    search_parser.add_argument('-k', '--key', help='Search by key')
    search_parser.add_argument('-t', '--time', default='today', help='Time range (today, yesterday, recent, or specific time)')
    search_parser.add_argument('-u', '--user', help='Filter by user (username or UID)')
    search_parser.add_argument('-f', '--file', help='Filter by file path')
    search_parser.add_argument('-m', '--syscall', help='Filter by syscall')
    search_parser.add_argument('-o', '--output', choices=['text', 'json'], default='text', help='Output format')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate reports')
    report_parser.add_argument('type', choices=['daily', 'user', 'summary'], help='Report type')
    report_parser.add_argument('--user', help='Username for user report')
    report_parser.add_argument('--time', default='today', help='Time range for report')
    
    # Incident response
    incident_parser = subparsers.add_parser('incident', help='Incident response scenarios')
    incident_parser.add_argument('scenario', choices=['ssh', 'backdoor', 'privilege', 'exfiltration', 'all'],
                               help='Incident scenario')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Live monitoring')
    monitor_parser.add_argument('--patterns', nargs='+', help='Patterns to monitor')
    
    # Alerts command
    subparsers.add_parser('alerts', help='Check security alerts')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export events')
    export_parser.add_argument('-f', '--format', choices=['json', 'csv', 'text'], default='json', help='Export format')
    export_parser.add_argument('-o', '--output', help='Output file path')
    
    # Investigate command
    investigate_parser = subparsers.add_parser('investigate', help='Targeted investigation')
    investigate_parser.add_argument('--file', help='Investigate specific file')
    investigate_parser.add_argument('--user', help='Investigate specific user')
    investigate_parser.add_argument('--time', help='Time range (start time)')
    investigate_parser.add_argument('--end', help='End time for time range')
    
    # Threat hunt command
    subparsers.add_parser('hunt', help='Quick threat hunt')
    
    # Checklist command
    subparsers.add_parser('checklist', help='Run morning checklist')
    
    args = parser.parse_args()
    
    # Create audit manager instance
    audit = AuditManager()
    
    # Execute commands
    if args.command == 'status':
        audit.check_status()
        
    elif args.command == 'apply':
        audit.apply_rules()
        
    elif args.command == 'search':
        result = audit.search(
            key=args.key,
            time_range=args.time,
            user=args.user,
            file_path=args.file,
            syscall=args.syscall,
            output_format=args.output
        )
        if args.output == 'json' and isinstance(result, dict):
            print(json.dumps(result, indent=2))
        else:
            print(result)
            
    elif args.command == 'report':
        if args.type == 'daily':
            audit.generate_daily_report()
        elif args.type == 'user':
            if args.user:
                audit.generate_user_report(args.user, args.time)
            else:
                print("❌ Please specify --user for user report")
        elif args.type == 'summary':
            stdout, _, _ = audit.run_command(['aureport', '--summary', '-ts', args.time])
            print(stdout)
            
    elif args.command == 'incident':
        audit.incident_response(args.scenario)
        
    elif args.command == 'monitor':
        audit.live_monitor(args.patterns)
        
    elif args.command == 'alerts':
        audit.check_alerts()
        
    elif args.command == 'export':
        audit.export_events(args.format, args.output)
        
    elif args.command == 'investigate':
        if args.file:
            audit.investigate_file(args.file)
        elif args.user:
            audit.generate_user_report(args.user)
        elif args.time:
            audit.investigate_time_range(args.time, args.end)
        else:
            print("❌ Please specify --file, --user, or --time")
            
    elif args.command == 'hunt':
        audit.quick_threat_hunt()
        
    elif args.command == 'checklist':
        audit.morning_checklist()
        
    else:
        parser.print_help()

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠️  This script requires root privileges. Attempting to use sudo...\n")
    
    main()
