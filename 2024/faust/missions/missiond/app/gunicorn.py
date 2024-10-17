import os



workers = int(os.environ.get('GUNICORN_PROCESSES', '20'))

threads = int(os.environ.get('GUNICORN_THREADS', '10'))

# timeout = int(os.environ.get('GUNICORN_TIMEOUT', '120'))

bind = os.environ.get('GUNICORN_BIND', '0.0.0.0:5000')

