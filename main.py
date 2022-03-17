import os
from dotenv import load_dotenv

import uvicorn

load_dotenv()

PORT = int(os.getenv('PORT', default='8000'))

if __name__ == '__main__':
    uvicorn('app.api:app', host='0.0.0.0', port=PORT)
