"""
WSGI Production Entry Point for SentinelX SIEM
Can be run with Gunicorn, Waitress, or uWSGI:
    gunicorn --workers 4 --bind 0.0.0.0:5000 wsgi:application
"""

from app import app as application

if __name__ == "__main__":
    application.run()
