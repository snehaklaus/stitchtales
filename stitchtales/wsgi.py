import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'stitchtales.settings')

application = get_wsgi_application()

# Vercel serverless handler
app = application