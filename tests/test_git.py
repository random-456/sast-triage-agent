"""Tests for git repository management."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
import subprocess

from sast_triage.git import clone_repository


class TestGitRepository(unittest.TestCase):
    """Test cases for git repository management."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.repo_url = "https://github.com/test/repo.git"
        self.target_dir = os.path.join(self.test_dir, "test_repo")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @patch("subprocess.run")
    def test_clone_repository_success(self, mock_run):
        """Test successful repository cloning."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        
        result = clone_repository(self.repo_url, self.target_dir)
        
        self.assertTrue(result)
        mock_run.assert_called_once()
        
        # Check the command arguments
        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args[0], "git")
        self.assertEqual(call_args[1], "clone")
        self.assertEqual(call_args[2], self.repo_url)
    
    def test_clone_repository_no_url(self):
        """Test cloning with no repository URL."""
        result = clone_repository("", self.target_dir)
        
        self.assertFalse(result)
    
    def test_clone_repository_existing_directory(self):
        """Test cloning when directory already exists."""
        # Create directory with content
        os.makedirs(self.target_dir)
        Path(os.path.join(self.target_dir, "test.txt")).touch()
        
        result = clone_repository(self.repo_url, self.target_dir)
        
        self.assertTrue(result)  # Should return True (assumes already cloned)
    
    @patch("subprocess.run")
    def test_clone_repository_git_not_found(self, mock_run):
        """Test cloning when git is not installed."""
        mock_run.side_effect = FileNotFoundError("git not found")
        
        result = clone_repository(self.repo_url, self.target_dir)
        
        self.assertFalse(result)
    
    @patch("subprocess.run")
    def test_clone_repository_git_error(self, mock_run):
        """Test cloning with git error."""
        mock_error = subprocess.CalledProcessError(
            1, 
            ["git", "clone"],
            stderr="fatal: repository not found"
        )
        mock_run.side_effect = mock_error
        
        result = clone_repository(self.repo_url, self.target_dir)
        
        self.assertFalse(result)
    
    @patch("subprocess.run")
    def test_clone_repository_already_exists_error(self, mock_run):
        """Test cloning when getting 'already exists' error."""
        mock_error = subprocess.CalledProcessError(
            128,
            ["git", "clone"],
            stderr="fatal: destination path 'repo' already exists and is not an empty directory"
        )
        mock_run.side_effect = mock_error
        
        result = clone_repository(self.repo_url, self.target_dir)
        
        self.assertTrue(result)  # Should return True (directory exists)
    


if __name__ == "__main__":
    unittest.main()