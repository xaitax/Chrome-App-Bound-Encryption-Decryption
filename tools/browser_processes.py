#!/usr/bin/env python3
"""
Browser Process Inspector
Enumerates all Chrome/Edge/Brave processes with their full command-line arguments.
Identifies Network Service processes that hold database file locks.
"""

import psutil
import sys
from collections import defaultdict

BROWSERS = {
    'chrome.exe': 'Chrome',
    'msedge.exe': 'Edge',
    'brave.exe': 'Brave'
}

def get_browser_processes():
    """Get all browser processes grouped by type."""
    browser_procs = defaultdict(list)
    
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'create_time']):
        try:
            name = proc.info['name'].lower() if proc.info['name'] else ''
            if name in BROWSERS:
                browser_procs[name].append({
                    'pid': proc.info['pid'],
                    'ppid': proc.info['ppid'],
                    'name': proc.info['name'],
                    'cmdline': proc.info['cmdline'] or [],
                    'create_time': proc.info['create_time']
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    return browser_procs

def identify_process_type(cmdline):
    """Identify the type of browser subprocess from command line."""
    cmdline_str = ' '.join(cmdline)
    
    if '--type=gpu-process' in cmdline_str:
        return 'GPU Process'
    if '--type=utility' in cmdline_str:
        if 'network.mojom.NetworkService' in cmdline_str:
            return '🔒 NETWORK SERVICE (holds DB locks)'
        if 'storage.mojom.StorageService' in cmdline_str:
            return '💾 Storage Service'
        if 'audio.mojom.AudioService' in cmdline_str:
            return '🔊 Audio Service'
        return 'Utility Process'
    if '--type=renderer' in cmdline_str:
        return 'Renderer'
    if '--type=crashpad-handler' in cmdline_str:
        return 'Crashpad Handler'
    if '--type=' not in cmdline_str and cmdline:
        return '🌐 MAIN BROWSER (parent)'
    
    return 'Unknown'

def build_process_tree(procs):
    """Build a parent-child tree of processes."""
    by_pid = {p['pid']: p for p in procs}
    children = defaultdict(list)
    roots = []
    
    for proc in procs:
        ppid = proc['ppid']
        if ppid in by_pid:
            children[ppid].append(proc)
        else:
            roots.append(proc)
    
    return roots, children

def print_tree(proc, children, indent=0):
    """Print process tree recursively."""
    cmdline = proc['cmdline']
    proc_type = identify_process_type(cmdline)
    
    prefix = '  ' * indent + ('└── ' if indent > 0 else '')
    
    # Highlight network service
    highlight = '\033[93m' if 'NETWORK SERVICE' in proc_type else ''
    reset = '\033[0m' if highlight else ''
    
    print(f"{prefix}{highlight}[PID {proc['pid']}] {proc_type}{reset}")
    
    # Show relevant command-line args
    relevant_args = [arg for arg in cmdline if any(k in arg for k in 
        ['--type=', '--utility-sub-type=', '--profile-directory=', '--user-data-dir='])]
    if relevant_args:
        for arg in relevant_args:
            print(f"{'  ' * (indent + 1)}    {arg}")
    
    # Recurse to children
    for child in sorted(children.get(proc['pid'], []), key=lambda x: x['create_time']):
        print_tree(child, children, indent + 1)

def main():
    print("\n" + "="*70)
    print("  Browser Process Inspector")
    print("="*70)
    
    browser_procs = get_browser_processes()
    
    if not browser_procs:
        print("\n  No browser processes found.\n")
        return
    
    total_network_services = 0
    
    for exe_name, procs in sorted(browser_procs.items()):
        browser_name = BROWSERS.get(exe_name, exe_name)
        
        print(f"\n┌──── {browser_name} ({len(procs)} processes) " + "─"*40)
        
        # Count network services
        network_count = sum(1 for p in procs if 'network.mojom.NetworkService' in ' '.join(p['cmdline']))
        total_network_services += network_count
        
        if network_count:
            print(f"│  ⚠️  {network_count} Network Service(s) holding file locks")
        
        roots, children = build_process_tree(procs)
        
        print("│")
        for root in sorted(roots, key=lambda x: x['create_time']):
            print_tree(root, children, indent=0)
        
        print(f"└{'─'*69}")
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"   Total Network Services: {total_network_services}")
    if total_network_services > 0:
        print(f"   ⚠️  These processes hold locks on Cookies, Login Data, Web Data databases")
        print(f"   The --utility-sub-type=network.mojom.NetworkService pattern should be targeted")
    
    print()

if __name__ == '__main__':
    main()
