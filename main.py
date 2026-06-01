#!/usr/bin/env python3
"""
PSADT-Secure Entry Point
Standalone PSADT v4 Package Security Scanner
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from scanners.scan_psadt import PSADTSecureScanner

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("PSADT-Secure: PSADT v4 Security Scanner")
        print("\nUsage:")
        print("  python main.py <package_path> [output_dir]")
        print("\nExample:")
        print("  python main.py C:\\SCCM\\Packages\\MyApp")
        print("  python main.py C:\\SCCM\\Packages\\MyApp C:\\Reports")
        sys.exit(1)
    
    package_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = PSADTSecureScanner(package_path, output_dir)
    findings = scanner.scan()
    scanner.print_summary()
    
    sys.exit(0 if findings['summary']['approval_status'] == "APPROVED" else 1)
