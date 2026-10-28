import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[3] / '.env', override=False)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = PROJECT_ROOT / 'backend'
ARTIFACTS_DIR = BACKEND_ROOT / 'artifacts'
DATASET_DIR = PROJECT_ROOT / 'datasets'

APP_NAME = os.getenv('APP_NAME', 'ThreatLens AI')
APP_ENV = os.getenv('APP_ENV', 'development')
API_HOST = os.getenv('API_HOST', '127.0.0.1')
API_PORT = int(os.getenv('API_PORT', '8000'))
FRONTEND_ORIGIN = os.getenv('FRONTEND_ORIGIN', 'http://localhost:5173')
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
MONGODB_DB = os.getenv('MONGODB_DB', 'threatlens')
MONGODB_ALERTS_COLLECTION = os.getenv('MONGODB_ALERTS_COLLECTION', 'alerts')
MONGODB_ANALYSIS_COLLECTION = os.getenv('MONGODB_ANALYSIS_COLLECTION', 'analysis_history')
MONGODB_MODEL_COLLECTION = os.getenv('MONGODB_MODEL_COLLECTION', 'model_metadata')
MONGODB_SETTINGS_COLLECTION = os.getenv('MONGODB_SETTINGS_COLLECTION', 'app_settings')
DEMO_MODE = os.getenv('DEMO_MODE', 'true').lower() == 'true'
MAX_UPLOAD_SIZE_MB = int(os.getenv('MAX_UPLOAD_SIZE_MB', '10'))
MAX_ROWS_PER_UPLOAD = int(os.getenv('MAX_ROWS_PER_UPLOAD', '5000'))
BATCH_SIZE = int(os.getenv('BATCH_SIZE', '50'))
DET_ALERT_THRESHOLD = float(os.getenv('DET_ALERT_THRESHOLD', '0.5'))
DET_RISK_THRESHOLD = float(os.getenv('DET_RISK_THRESHOLD', '65'))
DET_PORTSCAN_THRESHOLD = float(os.getenv('DET_PORTSCAN_THRESHOLD', '0.6'))
DET_DOS_THRESHOLD = float(os.getenv('DET_DOS_THRESHOLD', '0.7'))
DET_ANOMALY_THRESHOLD = float(os.getenv('DET_ANOMALY_THRESHOLD', '0.58'))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
