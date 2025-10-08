# PythonAnywhere WSGI Configuration
import sys
import os

# Add your project directory to sys.path
project_home = '/home/yourusername/url_detector'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set environment variables
os.environ['PYTHONPATH'] = project_home
os.environ['PORT'] = '8000'
os.environ['HOST'] = '0.0.0.0'

# Import your FastAPI application
from simplified_responsive_app import app

# WSGI application
application = app