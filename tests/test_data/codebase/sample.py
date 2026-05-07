# Sample Python file for testing search across multiple extensions
import os

def get_user_input():
    """Get user input from request."""
    user_id = input("Enter user ID: ")
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return query
