#!/usr/bin/env python3
"""
Unified Paste Scanner — Single entry point for all scanning tools.
Tool 1 (--mod1): Tor IP Rotation (ssavr, copy-paste.online, airforshare)
Tool 2 (--mod2): HTTP Proxy Brute-Forcer (cl1p, justpaste, rentry)
"""

import sys
import os
import subprocess
from pathlib import Path

def ensure_compiled():
    """Ensure the C extension is compiled for the current platform."""
    src_dir = Path(__file__).parent / "src"
    so_file = src_dir / "fast_utils.so"
    c_file = src_dir / "fast_utils.c"
    
    if not so_file.exists() and c_file.exists():
        print("  [ SETUP ] First time execution: Compiling C extensions for speed...")
        try:
            # Check if gcc is available
            subprocess.run(["gcc", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            
            # Compile
            subprocess.run([
                "gcc", "-shared", "-o", str(so_file), "-fPIC", str(c_file), "-O3"
            ], check=True)
            print("  [ SETUP ] ✓ Compiled successfully.\n")
        except FileNotFoundError:
            print("  [ ERROR ] 'gcc' compiler not found on your system.")
            print("  [ ERROR ] Please run: sudo apt install gcc")
            print("  [ ERROR ] Or use the provided installer: ./setup.sh")
            sys.exit(1)
        except subprocess.CalledProcessError:
            print("  [ ERROR ] Failed to compile fast_utils.c. Check your build environment.")
            sys.exit(1)

def show_help():
    print("""
============================================================
  🔍 UNIFIED PASTE SCANNER
============================================================

You must specify which module to run using a mandatory flag:

  --mod1    Run the Tor IP Rotation Tool 
            (Targets: ssavr.com, copy-paste.online, airforshare.com)

  --mod2    Run the HTTP Proxy Brute-Forcer 
            (Targets: cl1p.net, justpaste.it, rentry.co)

Examples:
  python3 main.py --mod1 -t SS --loop
  python3 main.py --mod1 -tsf altrooo/messaggiosavr.txt
  python3 main.py --mod2 -t cl1p -w "message"
  python3 main.py --mod2 -t all -wf target_file.txt
  python3 main.py --mod2 -t all --reset-all

For detailed help on a specific module, use:
  python3 main.py --mod1 --help
  python3 main.py --mod2 --help
============================================================
""")

def handle_maintenance():
    if "--uninstall" in sys.argv or "--clean-data" in sys.argv:
        import shutil
        from src import config
        print("  [ CLEAN ] Removing generated data...")
        
        # Remove data folder contents
        if config.DATA_DIR.exists():
            for item in config.DATA_DIR.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)
                    print(f"   ✓ Removed {item.name}/")
                else:
                    item.unlink()
                    print(f"   ✓ Removed {item.name}")
        
        # Remove log files in root
        for f in ["changes.txt", "ssavr_clean.txt", "copypaste_clean.txt", "airforshare_clean.txt", "cl1p_clean.txt", "justpaste_clean.txt", "rentry_clean.txt"]:
            p = config.BASE_DIR / f
            if p.exists():
                p.unlink()
                print(f"   ✓ Removed {f}")
            p_dedup = config.BASE_DIR / f.replace(".txt", "_dedup.json")
            if p_dedup.exists():
                p_dedup.unlink()
                print(f"   ✓ Removed {f.replace('.txt', '_dedup.json')}")
        
        print("\n  ✓ All generated data removed!")
        
        if "--uninstall" in sys.argv:
            print("\n  📦 The program is fully self-contained.")
            print("  📦 To completely uninstall, simply delete this entire folder:")
            print(f"   rm -rf {config.BASE_DIR}\n")
        sys.exit(0)

def main():
    handle_maintenance()
    ensure_compiled()

    if "--mod1" in sys.argv:
        sys.argv.remove("--mod1")
        from src.tor_scanner import main as tor_main
        tor_main()
        return

    if "--mod2" in sys.argv:
        sys.argv.remove("--mod2")
        from src.proxy_scanner import main as proxy_main
        proxy_main()
        return

    # If neither flag is provided, or the user ran something invalid without arguments
    show_help()

if __name__ == "__main__":
    main()
