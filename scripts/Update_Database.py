"""
Script to run all ingestion feeds and pull data into the database.
    - From the dashboard: Click the "Update All Feeds" button on the Threat Feeds page.
    - From the command line: Run `python scripts/Update_Database.py`
"""

import os
import sys
import django

# Setup Django environment
if __name__ == "__main__":
    # Add the parent directory to the Python path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Configure Django settings
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cti.settings')
    django.setup()
    
    # Import and run the management command
    from django.core.management import call_command
    
    print("Starting database update from all threat feeds...")
    try:
        call_command('ingest_all')
        print("Database update completed successfully.")
    except Exception as e:
        print(f"Error during database update: {e}")
        sys.exit(1)
