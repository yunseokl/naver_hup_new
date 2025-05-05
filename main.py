import logging
import os
from app import app

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Make sure the uploads directory exists
os.makedirs('uploads', exist_ok=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
