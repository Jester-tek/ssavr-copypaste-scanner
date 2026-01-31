import os
import sys
import subprocess
from . import config

def check_for_updates():
    print("\n" + "="*80)
    print("🔄 CHECKING FOR UPDATES")
    print("="*80)
    try:
        # We need the root of the repo, which is config.BASE_DIR
        script_dir = config.BASE_DIR
        
        # Check if git repo
        result = subprocess.run(['git', 'rev-parse', '--git-dir'], cwd=script_dir, capture_output=True, text=True)
        if result.returncode != 0:
            print("✗ Not a git repository. Please clone from GitHub:")
            print(f"  git clone {config.REPO_URL}")
            return

        print("📡 Fetching latest version from GitHub...")
        subprocess.run(['git', 'fetch'], cwd=script_dir, check=True)
        
        # Check how many commits behind
        result = subprocess.run(['git', 'rev-list', 'HEAD..origin/main', '--count'], cwd=script_dir, capture_output=True, text=True)
        commits_behind = int(result.stdout.strip())
        
        if commits_behind == 0:
            print("✅ You're already on the latest version!")
            return

        print(f"📦 {commits_behind} update(s) available")
        print("\n📋 Changes:")
        subprocess.run(['git', 'log', 'HEAD..origin/main', '--oneline'], cwd=script_dir)
        
        response = input("\n⚠️  Update now? (y/n): ").lower().strip()
        if response == 'y':
            print("\n🔄 Updating...")
            print("💾 Preserving configuration and log files...")
            # Stash changes (like config or logs if not ignored)
            subprocess.run(['git', 'stash', 'push', '-m', 'Auto-stash before update', 'data/', '*.txt'], cwd=script_dir)
            
            subprocess.run(['git', 'pull', 'origin', 'main'], cwd=script_dir, check=True)
            
            print("📂 Restoring local changes (logs/config)...")
            try:
                subprocess.run(['git', 'stash', 'pop'], cwd=script_dir, check=True)
            except subprocess.CalledProcessError:
                print("⚠ Rewrite conflict during stash pop - your local configs might need manual merge check.")
            
            print("\n✅ Update completed successfully!")
            print("🔄 Please restart the script to use the new version")
            sys.exit(0)
        else:
            print("❌ Update cancelled")
            
    except subprocess.CalledProcessError as e:
        print(f"✗ Error during update: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
