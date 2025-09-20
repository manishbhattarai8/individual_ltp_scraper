import requests
from bs4 import BeautifulSoup
import json
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_cors import CORS
import logging
import os
import ssl
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
import hashlib
import secrets
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_security_tables()
    
    def init_security_tables(self):
        """Initialize security-related tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # API Keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT UNIQUE NOT NULL,
                key_hash TEXT NOT NULL,
                key_type TEXT NOT NULL CHECK (key_type IN ('admin', 'regular')),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                last_used DATETIME,
                max_devices INTEGER DEFAULT 1,
                description TEXT
            )
        ''')
        
        # Device sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_info TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (key_id) REFERENCES api_keys (key_id),
                UNIQUE(key_id, device_id)
            )
        ''')
        
        # API usage logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT,
                device_id TEXT,
                endpoint TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (key_id) REFERENCES api_keys (key_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_key_id ON api_keys(key_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_device_sessions_key_device ON device_sessions(key_id, device_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_logs_key_timestamp ON api_logs(key_id, timestamp)')
        
        conn.commit()
        conn.close()
        logger.info("Security tables initialized successfully")
    
    def generate_key_pair(self, key_type='regular', created_by='system', description=''):
        """Generate a new API key pair"""
        # Generate a secure random key
        key = secrets.token_urlsafe(32)
        key_id = f"npse_{key_type}_{secrets.token_urlsafe(8)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        max_devices = 5 if key_type == 'admin' else 1
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO api_keys (key_id, key_hash, key_type, created_by, max_devices, description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (key_id, key_hash, key_type, created_by, max_devices, description))
            
            conn.commit()
            logger.info(f"Generated new {key_type} key: {key_id}")
            
            return {
                'key_id': key_id,
                'api_key': key,
                'key_type': key_type,
                'max_devices': max_devices,
                'created_at': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error generating key: {e}")
            return None
        finally:
            conn.close()
    
    def validate_key(self, api_key, device_id, device_info='', endpoint='', ip_address='', user_agent=''):
        """Validate an API key and manage device sessions"""
        if not api_key or not device_id:
            return {'valid': False, 'error': 'Missing API key or device ID'}
        
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if key exists and is active
            cursor.execute('''
                SELECT key_id, key_type, max_devices, is_active 
                FROM api_keys 
                WHERE key_hash = ? AND is_active = TRUE
            ''', (key_hash,))
            
            key_record = cursor.fetchone()
            if not key_record:
                self._log_api_usage(cursor, None, device_id, endpoint, ip_address, user_agent)
                return {'valid': False, 'error': 'Invalid API key'}
            
            key_id, key_type, max_devices, is_active = key_record
            
            # Update last used time for the key
            cursor.execute('UPDATE api_keys SET last_used = ? WHERE key_id = ?', 
                          (datetime.now(), key_id))
            
            # Check existing device sessions
            cursor.execute('''
                SELECT COUNT(*) FROM device_sessions 
                WHERE key_id = ? AND is_active = TRUE
            ''', (key_id,))
            
            active_devices = cursor.fetchone()[0]
            
            # Check if this specific device is already registered
            cursor.execute('''
                SELECT id FROM device_sessions 
                WHERE key_id = ? AND device_id = ? AND is_active = TRUE
            ''', (key_id, device_id))
            
            existing_session = cursor.fetchone()
            
            if existing_session:
                # Update existing session
                cursor.execute('''
                    UPDATE device_sessions 
                    SET last_activity = ?, device_info = ?
                    WHERE key_id = ? AND device_id = ?
                ''', (datetime.now(), device_info, key_id, device_id))
            else:
                # Check if we can add a new device
                if active_devices >= max_devices:
                    self._log_api_usage(cursor, key_id, device_id, endpoint, ip_address, user_agent)
                    return {'valid': False, 'error': f'Maximum devices ({max_devices}) reached for this key'}
                
                # Create new device session
                cursor.execute('''
                    INSERT INTO device_sessions (key_id, device_id, device_info, last_activity)
                    VALUES (?, ?, ?, ?)
                ''', (key_id, device_id, device_info, datetime.now()))
            
            # Log API usage
            self._log_api_usage(cursor, key_id, device_id, endpoint, ip_address, user_agent)
            
            conn.commit()
            
            return {
                'valid': True,
                'key_id': key_id,
                'key_type': key_type,
                'max_devices': max_devices,
                'active_devices': active_devices if not existing_session else active_devices
            }
            
        except Exception as e:
            logger.error(f"Error validating key: {e}")
            return {'valid': False, 'error': 'Validation error'}
        finally:
            conn.close()
    
    def _log_api_usage(self, cursor, key_id, device_id, endpoint, ip_address, user_agent):
        """Log API usage"""
        try:
            cursor.execute('''
                INSERT INTO api_logs (key_id, device_id, endpoint, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            ''', (key_id, device_id, endpoint, ip_address, user_agent))
        except Exception as e:
            logger.warning(f"Failed to log API usage: {e}")
    
    def get_key_info(self, key_id):
        """Get information about a specific key"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT k.key_id, k.key_type, k.created_at, k.created_by, k.is_active, 
                       k.last_used, k.max_devices, k.description,
                       COUNT(d.id) as active_devices
                FROM api_keys k
                LEFT JOIN device_sessions d ON k.key_id = d.key_id AND d.is_active = TRUE
                WHERE k.key_id = ?
                GROUP BY k.key_id
            ''', (key_id,))
            
            result = cursor.fetchone()
            if result:
                return {
                    'key_id': result[0],
                    'key_type': result[1],
                    'created_at': result[2],
                    'created_by': result[3],
                    'is_active': bool(result[4]),
                    'last_used': result[5],
                    'max_devices': result[6],
                    'description': result[7],
                    'active_devices': result[8]
                }
            return None
        finally:
            conn.close()
    
    def list_all_keys(self):
        """List all keys (for admin use)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT k.key_id, k.key_type, k.created_at, k.created_by, k.is_active, 
                       k.last_used, k.max_devices, k.description,
                       COUNT(d.id) as active_devices
                FROM api_keys k
                LEFT JOIN device_sessions d ON k.key_id = d.key_id AND d.is_active = TRUE
                GROUP BY k.key_id
                ORDER BY k.created_at DESC
            ''')
            
            keys = []
            for row in cursor.fetchall():
                keys.append({
                    'key_id': row[0],
                    'key_type': row[1],
                    'created_at': row[2],
                    'created_by': row[3],
                    'is_active': bool(row[4]),
                    'last_used': row[5],
                    'max_devices': row[6],
                    'description': row[7],
                    'active_devices': row[8]
                })
            return keys
        finally:
            conn.close()
    
    def deactivate_key(self, key_id):
        """Deactivate a key and all its sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('UPDATE api_keys SET is_active = FALSE WHERE key_id = ?', (key_id,))
            cursor.execute('UPDATE device_sessions SET is_active = FALSE WHERE key_id = ?', (key_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    def cleanup_old_sessions(self, days=30):
        """Clean up old inactive sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        try:
            cursor.execute('''
                DELETE FROM device_sessions 
                WHERE last_activity < ? AND is_active = FALSE
            ''', (cutoff_date,))
            
            cursor.execute('''
                DELETE FROM api_logs 
                WHERE timestamp < ?
            ''', (cutoff_date,))
            
            conn.commit()
            logger.info(f"Cleaned up old sessions and logs older than {days} days")
        finally:
            conn.close()

# Your existing NepalStockScraper class remains the same
class NepalStockScraper:
    def __init__(self, db_path='nepal_stock.db'):
        self.db_path = db_path
        # Primary source: ShareSansar live trading page
        self.urls = [
            'https://www.sharesansar.com/live-trading',
            'https://merolagani.com/LatestMarket.aspx',
            'https://www.sharesansar.com/today-share-price'
        ]
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Configure session with retry strategy and SSL handling
        self.session = requests.Session()
        
        # Disable SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        # Mount adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create stocks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                symbol TEXT NOT NULL,
                company_name TEXT,
                ltp REAL,  -- Last Traded Price
                change REAL,
                change_percent REAL,
                high REAL,
                low REAL,
                open_price REAL,
                qty INTEGER,
                turnover REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(symbol, timestamp)
            )
        ''')
        
        # Create index for better query performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_symbol_timestamp 
            ON stocks(symbol, timestamp)
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    # [Include all your existing scraper methods here - scrape_stock_data, parse_stock_data, etc.]
    # I'm keeping them as they are to focus on the security implementation
    
    def get_latest_data(self, symbol=None):
        """Get latest stock data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if symbol:
            cursor.execute('''
                SELECT * FROM stocks 
                WHERE symbol = ? 
                ORDER BY timestamp DESC 
                LIMIT 1
            ''', (symbol.upper(),))
        else:
            cursor.execute('''
                SELECT s1.* FROM stocks s1
                INNER JOIN (
                    SELECT symbol, MAX(timestamp) as max_timestamp
                    FROM stocks
                    GROUP BY symbol
                ) s2 ON s1.symbol = s2.symbol AND s1.timestamp = s2.max_timestamp
                ORDER BY s1.symbol
            ''')
        
        columns = [description[0] for description in cursor.description]
        results = []
        
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        conn.close()
        return results

# Flask API with Security
app = Flask(__name__)
CORS(app)
scraper = NepalStockScraper()
security_manager = SecurityManager(scraper.db_path)

def require_auth(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        device_id = request.headers.get('X-Device-ID') or request.args.get('device_id')
        device_info = request.headers.get('X-Device-Info', '')
        
        if not api_key or not device_id:
            return jsonify({
                'success': False,
                'error': 'API key and device ID are required'
            }), 401
        
        validation = security_manager.validate_key(
            api_key=api_key,
            device_id=device_id,
            device_info=device_info,
            endpoint=request.endpoint,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        
        if not validation['valid']:
            return jsonify({
                'success': False,
                'error': validation['error']
            }), 401
        
        # Add key info to request context
        request.key_info = validation
        return f(*args, **kwargs)
    
    return decorated_function

def require_admin(f):
    """Decorator to require admin key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(request, 'key_info') or request.key_info.get('key_type') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Admin access required'
            }), 403
        return f(*args, **kwargs)
    
    return decorated_function

# Public endpoints (no auth required)
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

# Protected endpoints (require API key)
@app.route('/api/stocks', methods=['GET'])
@require_auth
def get_stocks():
    """API endpoint to get all latest stock data"""
    try:
        symbol = request.args.get('symbol')
        data = scraper.get_latest_data(symbol)
        return jsonify({
            'success': True,
            'data': data,
            'count': len(data),
            'timestamp': datetime.now().isoformat(),
            'key_info': {
                'key_type': request.key_info['key_type'],
                'key_id': request.key_info['key_id']
            }
        })
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stocks/<symbol>', methods=['GET'])
@require_auth
def get_stock_by_symbol(symbol):
    """API endpoint to get specific stock data"""
    try:
        data = scraper.get_latest_data(symbol.upper())
        if data:
            return jsonify({
                'success': True,
                'data': data[0],
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Stock not found'
            }), 404
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/trigger-scrape', methods=['POST'])
@require_auth
def trigger_scrape():
    """Manual trigger for scraping"""
    try:
        logger.info(f"Manual scrape triggered by {request.key_info['key_id']}")
        # scraper.run_scraper()  # Implement your scraper logic
        return jsonify({
            'success': True,
            'message': 'Scraping completed successfully'
        })
    except Exception as e:
        logger.error(f"Manual scrape failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Admin endpoints
@app.route('/api/admin/generate-key', methods=['POST'])
@require_auth
@require_admin
def generate_api_key():
    """Generate a new API key (admin only)"""
    try:
        data = request.get_json() or {}
        key_type = data.get('key_type', 'regular')
        description = data.get('description', '')
        
        if key_type not in ['admin', 'regular']:
            return jsonify({
                'success': False,
                'error': 'Invalid key type. Must be "admin" or "regular"'
            }), 400
        
        key_pair = security_manager.generate_key_pair(
            key_type=key_type,
            created_by=request.key_info['key_id'],
            description=description
        )
        
        if key_pair:
            return jsonify({
                'success': True,
                'key_pair': key_pair
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to generate key'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/admin/keys', methods=['GET'])
@require_auth
@require_admin
def list_keys():
    """List all API keys (admin only)"""
    try:
        keys = security_manager.list_all_keys()
        return jsonify({
            'success': True,
            'keys': keys
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/admin/keys/<key_id>/deactivate', methods=['POST'])
@require_auth
@require_admin
def deactivate_key(key_id):
    """Deactivate a key (admin only)"""
    try:
        success = security_manager.deactivate_key(key_id)
        if success:
            return jsonify({
                'success': True,
                'message': f'Key {key_id} deactivated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Key not found'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/admin/cleanup', methods=['POST'])
@require_auth
@require_admin
def admin_cleanup():
    """Cleanup old sessions and logs (admin only)"""
    try:
        days = int(request.args.get('days', 30))
        security_manager.cleanup_old_sessions(days)
        return jsonify({
            'success': True,
            'message': f'Cleanup completed for data older than {days} days'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/key-info', methods=['GET'])
@require_auth
def get_current_key_info():
    """Get information about the current key"""
    try:
        key_info = security_manager.get_key_info(request.key_info['key_id'])
        return jsonify({
            'success': True,
            'key_info': key_info
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Create initial admin key if none exists
    conn = sqlite3.connect(scraper.db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM api_keys WHERE key_type = "admin" AND is_active = TRUE')
    admin_count = cursor.fetchone()[0]
    conn.close()
    
    if admin_count == 0:
        logger.info("No admin keys found, creating initial admin key...")
        initial_admin = security_manager.generate_key_pair(
            key_type='admin',
            created_by='system',
            description='Initial admin key'
        )
        if initial_admin:
            logger.info("=" * 60)
            logger.info("INITIAL ADMIN KEY CREATED:")
            logger.info(f"Key ID: {initial_admin['key_id']}")
            logger.info(f"API Key: {initial_admin['api_key']}")
            logger.info("SAVE THIS KEY SECURELY - IT WON'T BE SHOWN AGAIN!")
            logger.info("=" * 60)
    
    # Start Flask app
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting secured Flask app on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)