"""Git repository management utilities."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional


def clone_repository(
    repo_url: str, 
    target_dir: str, 
    quiet: bool = True
) -> bool:
    """
    Clone a git repository to the specified directory.
    
    Args:
        repo_url: The URL of the git repository
        target_dir: The target directory for cloning
        quiet: Whether to suppress git output
        
    Returns:
        True if successful, False otherwise
    """
    if not repo_url:
        print("No repository URL provided, skipping clone.")
        return False
    
    target_path = Path(target_dir)
    
    # Check if directory already exists and has content
    if target_path.exists() and any(target_path.iterdir()):
        print(f"Directory {target_dir} already exists and is not empty.")
        print("Assuming repository is already cloned.")
        return True
    
    print(f"Cloning repository from {repo_url}...")
    
    try:
        # Ensure parent directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Prepare git command
        cmd = ["git", "clone", repo_url, str(target_path)]
        if quiet:
            cmd.append("--quiet")
        
        # Execute git clone
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        print("Repository cloned successfully.")
        return True
        
    except FileNotFoundError:
        print("ERROR: 'git' command not found. Please ensure Git is installed.")
        return False
        
    except subprocess.CalledProcessError as e:
        if "already exists and is not an empty directory" in e.stderr:
            print("Directory already contains a repository.")
            return True
        else:
            print(f"ERROR: Failed to clone repository: {e.returncode}")
            if e.stderr:
                print(f"Error details: {e.stderr}")
            return False
    
    except Exception as e:
        print(f"ERROR: Unexpected error while cloning: {e}")
        return False


def cleanup_repository(target_dir: str) -> bool:
    """
    Remove the cloned repository directory.
    
    Args:
        target_dir: The directory to remove
        
    Returns:
        True if successful, False otherwise
    """
    target_path = Path(target_dir)
    
    if not target_path.exists():
        print(f"Directory {target_dir} does not exist, nothing to clean.")
        return True
    
    print(f"Cleaning up repository at {target_dir}...")
    
    try:
        shutil.rmtree(target_path)
        print("Repository cleaned up successfully.")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to clean up repository: {e}")
        return False