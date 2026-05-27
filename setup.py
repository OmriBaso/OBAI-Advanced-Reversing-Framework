#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Setup script for Ghidra Reverse Engineering Platform
Installs dependencies and configures ghidra_bridge server
"""

import os
import sys
import subprocess
from pathlib import Path


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def install_requirements():
    """Install Python dependencies from requirements.txt"""
    print_section("Installing Python Dependencies")
    
    req_file = Path(__file__).parent / "requirements.txt"
    
    if not req_file.exists():
        print("❌ ERROR: requirements.txt not found!")
        return False
    
    try:
        print(f"📦 Installing packages from: {req_file}")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", str(req_file)
        ])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: Failed to install dependencies: {e}")
        return False


def setup_ghidra_bridge():
    """Install ghidra_bridge server script to ghidra_scripts directory"""
    print_section("Configuring Ghidra Bridge Server")
    
    # Get ghidra_scripts path (same directory as app.py)
    scripts_dir = Path(__file__).parent / "ghidra_scripts"
    
    # Create directory if it doesn't exist
    scripts_dir.mkdir(exist_ok=True)
    print(f"📂 Using scripts directory: {scripts_dir}")
    
    try:
        # Install ghidra_bridge server to the scripts directory
        print("🔧 Installing ghidra_bridge server script...")
        subprocess.check_call([
            sys.executable, "-m", "ghidra_bridge.install_server", str(scripts_dir)
        ])
        print(f"✅ Ghidra bridge server installed to: {scripts_dir}")
        
        # Verify installation
        server_script = scripts_dir / "ghidra_bridge_server.py"
        if server_script.exists():
            print(f"✅ Verified: {server_script.name} exists")
        else:
            print("⚠️  WARNING: Server script not found after installation")
            
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: Failed to install ghidra_bridge server: {e}")
        print("\nTroubleshooting:")
        print("  1. Ensure ghidra_bridge is installed: pip install ghidra_bridge")
        print("  2. Check that the ghidra_scripts directory is writable")
        return False


def verify_environment():
    """Verify environment variables are set"""
    print_section("Verifying Environment Configuration")
    
    required_vars = {
        "GHIDRA_HOME": "Path to Ghidra installation (e.g., C:\\ghidra_11.4.2_PUBLIC)",
        "GHIDRA_SCRIPTS": "Path to Ghidra scripts directory",
        "GHIDRA_PROJECT_ROOT": "Path to store Ghidra project files"
    }
    
    all_set = True
    for var, description in required_vars.items():
        value = os.environ.get(var)
        if value:
            print(f"✅ {var}: {value}")
        else:
            print(f"⚠️  {var}: NOT SET")
            print(f"   Description: {description}")
            all_set = False
    
    if not all_set:
        print("\n" + "!" * 70)
        print("  WARNING: Some environment variables are not set!")
        print("!" * 70)
        print("\nYou need to set these before running the application:")
        print("\nOn Windows (PowerShell):")
        print('  $env:GHIDRA_HOME = "C:\\path\\to\\ghidra_11.4.2_PUBLIC"')
        print('  $env:GHIDRA_SCRIPTS = "C:\\path\\to\\your\\ghidra_scripts"')
        print('  $env:GHIDRA_PROJECT_ROOT = "C:\\path\\to\\ghidra_projects"')
        print("\nOn Windows (CMD):")
        print('  set GHIDRA_HOME=C:\\path\\to\\ghidra_11.4.2_PUBLIC')
        print('  set GHIDRA_SCRIPTS=C:\\path\\to\\your\\ghidra_scripts')
        print('  set GHIDRA_PROJECT_ROOT=C:\\path\\to\\ghidra_projects')
        print("\nOn Linux/Mac:")
        print('  export GHIDRA_HOME="/path/to/ghidra_11.4.2_PUBLIC"')
        print('  export GHIDRA_SCRIPTS="/path/to/your/ghidra_scripts"')
        print('  export GHIDRA_PROJECT_ROOT="/path/to/ghidra_projects"')
    
    return all_set


def create_directories():
    """Create necessary directories"""
    print_section("Creating Directory Structure")
    
    dirs = [
        "uploads",
        "analysis_db",
        "ghidra_scripts",
        "static"
    ]
    
    base_path = Path(__file__).parent
    
    for dir_name in dirs:
        dir_path = base_path / dir_name
        dir_path.mkdir(exist_ok=True)
        print(f"✅ Created/verified: {dir_path}")


def main():
    """Main setup routine"""
    print("\n" + "=" * 70)
    print("  🔧 Ghidra Reverse Engineering Platform - Setup")
    print("=" * 70)
    
    # Step 1: Install Python dependencies
    if not install_requirements():
        print("\n❌ Setup failed at dependency installation")
        return 1
    
    # Step 2: Setup ghidra_bridge server
    if not setup_ghidra_bridge():
        print("\n❌ Setup failed at ghidra_bridge configuration")
        return 1
    
    # Step 3: Create necessary directories
    create_directories()
    
    # Step 4: Verify environment (non-blocking)
    verify_environment()
    
    # Success!
    print_section("Setup Complete!")
    print("✅ All components installed successfully!")
    print("\n📝 Next steps:")
    print("  1. Set environment variables if not already set (see warnings above)")
    print("  2. Ensure Ghidra is installed and GHIDRA_HOME points to it")
    print("  3. Run the application: python app.py")
    print("  4. Access the web interface at: http://localhost:5000")
    print("\n" + "=" * 70 + "\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
