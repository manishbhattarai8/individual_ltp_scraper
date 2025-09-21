import requests
from bs4 import BeautifulSoup
import json
import sqlite3
from datetime import datetime, timedelta, time, timezone
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
import threading
import time as time_module

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MarketHours:
    """Handle NEPSE market hours and trading day logic"""
    
    def __init__(self):
        # Nepal timezone (UTC+5:45)
        self.nepal_tz = timezone(timedelta(hours=5, minutes=45))
        
        # NEPSE trading hours (Sunday to Thursday, 12:00 PM to 3:00 PM)
        self.market_open_time = time(12, 0)  # 12:00 PM
        self.market_close_time = time(15, 0)  # 3:00 PM
        
        # Trading days (0=Monday, 6=Sunday)
        self.trading_days = [6, 0, 1, 2, 3]  # Sunday to Thursday
    
    def get_nepal_time(self):
        """Get current Nepal time"""
        return datetime.now(self.nepal_tz)
    
    def is_trading_day(self, dt=None):
        """Check if given date is a trading day"""
        if dt is None:
            dt = self.get_nepal_time()
        return dt.weekday() in self.trading_days
    
    def is_market_hours(self, dt=None):
        """Check if current time is within market hours"""
        if dt is None:
            dt = self.get_nepal_time()
        
        if not self.is_trading_day(dt):
            return False
        
        current_time = dt.time()
        return self.market_open_time <= current_time <= self.market_close_time
    
    def is_market_open(self, dt=None):
        """Check if market is currently open"""
        return self.is_trading_day(dt) and self.is_market_hours(dt)
    
    def next_market_open(self):
        """Get the next market opening time"""
        now = self.get_nepal_time()
        
        # If market is currently open, return current time
        if self.is_market_open(now):
            return now
        
        # Check today first
        today_open = now.replace(hour=12, minute=0, second=0, microsecond=0)
        if self.is_trading_day(now) and now.time() < self.market_open_time:
            return today_open
        
        # Find next trading day
        for i in range(1, 8):  # Check next 7 days
            next_day = now + timedelta(days=i)
            if self.is_trading_day(next_day):
                return next_day.replace(hour=12, minute=0, second=0, microsecond=0)
        
        return today_open  # Fallback
    
    def time_to_market_open(self):
        """Get seconds until next market open"""
        now = self.get_nepal_time()
        next_open = self.next_market_open()
        return max(0, (next_open - now).total_seconds())
    
    def get_market_status(self):
        """Get current market status"""
        now = self.get_nepal_time()
        
        if not self.is_trading_day(now):
            return {
                'status': 'closed',
                'reason': 'Not a trading day',
                'next_open': self.next_market_open().isoformat()
            }
        
        if self.is_market_hours(now):
            return {
                'status': 'open',
                'reason': 'Market is open',
                'closes_at': now.replace(hour=15, minute=0, second=0, microsecond=0).isoformat()
            }
        
        current_time = now.time()
        if current_time < self.market_open_time:
            return {
                'status': 'pre_market',
                'reason': 'Before market hours',
                'opens_at': now.replace(hour=12, minute=0, second=0, microsecond=0).isoformat()
            }
        else:
            return {
                'status': 'after_hours',
                'reason': 'After market hours',
                'next_open': self.next_market_open().isoformat()
            }

class SecurityManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_security_tables()
    
    def init_security_tables(self):
        """Initialize security-related tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enable foreign key constraints
        cursor.execute('PRAGMA foreign_keys = ON')
        
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
                FOREIGN KEY (key_id) REFERENCES api_keys (key_id) ON DELETE CASCADE,
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
                FOREIGN KEY (key_id) REFERENCES api_keys (key_id) ON DELETE SET NULL
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
        cursor.execute('PRAGMA foreign_keys = ON')
        
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
        cursor.execute('PRAGMA foreign_keys = ON')
        
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
    
    def delete_key(self, key_id):
        """Delete a key and all associated data from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('PRAGMA foreign_keys = ON')
        
        try:
            # Check if key exists
            cursor.execute('SELECT key_id FROM api_keys WHERE key_id = ?', (key_id,))
            if not cursor.fetchone():
                return False
            
            # Delete the key (CASCADE will handle device_sessions, api_logs will have key_id set to NULL)
            cursor.execute('DELETE FROM api_keys WHERE key_id = ?', (key_id,))
            
            # Verify deletion
            deleted_count = cursor.rowcount
            conn.commit()
            
            if deleted_count > 0:
                logger.info(f"Successfully deleted key: {key_id}")
                return True
            else:
                logger.warning(f"No key found to delete: {key_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting key {key_id}: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()

class NepalStockScraper:
    def __init__(self, db_path='nepal_stock.db'):
        self.db_path = db_path
        self.market_hours = MarketHours()
        
        # Enhanced source list with better selectors
        self.sources = [
            {
                'name': 'ShareSansar Live Trading',
                'url': 'https://www.sharesansar.com/live-trading',
                'parser': 'parse_sharesansar_live'
            },
            {
                'name': 'ShareSansar Today Price',
                'url': 'https://www.sharesansar.com/today-share-price',
                'parser': 'parse_sharesansar_today'
            },
            {
                'name': 'MeroLagani Latest Market',
                'url': 'https://merolagani.com/LatestMarket.aspx',
                'parser': 'parse_merolagani'
            },
            {
                'name': 'NEPSE Official',
                'url': 'https://www.nepalstock.com/company/display/0',
                'parser': 'parse_nepse_official'
            }
        ]
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,ne;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        # Configure session
        self.session = requests.Session()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Scraping control
        self.last_scrape_time = None
        self.scrape_lock = threading.Lock()
        self.scheduler_thread = None
        self.should_stop_scheduler = False
        
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create stocks table with enhanced schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                symbol TEXT NOT NULL,
                company_name TEXT,
                ltp REAL,
                change REAL,
                change_percent REAL,
                high REAL,
                low REAL,
                open_price REAL,
                prev_close REAL,
                qty INTEGER,
                turnover REAL,
                trades INTEGER DEFAULT 0,
                source TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_latest BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_symbol_timestamp ON stocks(symbol, timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_symbol_latest ON stocks(symbol, is_latest)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON stocks(timestamp)')
        
        # Create scraping log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scrape_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT,
                status TEXT,
                stocks_found INTEGER DEFAULT 0,
                error_message TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    def should_scrape_now(self, force=False):
        """Determine if we should scrape now based on market hours and timing"""
        if force:
            logger.info("Forced scrape requested")
            return True, "Forced scrape"
        
        # Check if we've scraped recently (within 25 minutes to allow some buffer)
        if self.last_scrape_time:
            time_since_last = datetime.now() - self.last_scrape_time
            if time_since_last < timedelta(minutes=25):
                return False, f"Last scraped {time_since_last.seconds // 60} minutes ago"
        
        market_status = self.market_hours.get_market_status()
        
        # Always scrape during market hours
        if market_status['status'] == 'open':
            return True, "Market is open"
        
        # Scrape once after market closes (for final prices)
        if market_status['status'] == 'after_hours':
            if not self.last_scrape_time or self.last_scrape_time.date() < datetime.now().date():
                return True, "After hours - getting final prices"
        
        # Don't scrape on non-trading days or outside reasonable hours
        return False, f"Market status: {market_status['status']} - {market_status['reason']}"
    
    def _map_columns(self, header_texts):
        """Map column positions based on header text content"""
        column_map = {}
        
        for i, header in enumerate(header_texts):
            header_clean = header.lower().strip()
            
            # Symbol mapping
            if any(keyword in header_clean for keyword in ['symbol', 'scrip', 'stock', 'company']):
                if 'symbol' not in column_map:
                    column_map['symbol'] = i
                if any(keyword in header_clean for keyword in ['name', 'company']):
                    column_map['company_name'] = i
            
            # Price mappings
            if any(keyword in header_clean for keyword in ['ltp', 'price', 'last', 'current']):
                column_map['ltp'] = i
            elif any(keyword in header_clean for keyword in ['open', 'opening']):
                column_map['open'] = i
            elif any(keyword in header_clean for keyword in ['high', 'max']):
                column_map['high'] = i
            elif any(keyword in header_clean for keyword in ['low', 'min']):
                column_map['low'] = i
            elif any(keyword in header_clean for keyword in ['close', 'prev', 'previous']):
                column_map['prev_close'] = i
            elif any(keyword in header_clean for keyword in ['change', 'diff']):
                if '%' in header_clean or 'percent' in header_clean:
                    column_map['change_percent'] = i
                else:
                    column_map['change'] = i
            
            # Volume mappings
            elif any(keyword in header_clean for keyword in ['qty', 'volume', 'quantity']):
                column_map['qty'] = i
            elif any(keyword in header_clean for keyword in ['turnover', 'value']):
                column_map['turnover'] = i
            elif any(keyword in header_clean for keyword in ['trades', 'transaction']):
                column_map['trades'] = i
        
        return column_map
    
    def _is_valid_stock_table(self, table):
        """Check if a table contains valid stock data"""
        rows = table.find_all('tr')
        if len(rows) < 2:  # Need at least header + 1 data row
            return False
        
        # Check if we have enough columns
        first_data_row = rows[1] if len(rows) > 1 else rows[0]
        cols = first_data_row.find_all(['td', 'th'])
        if len(cols) < 3:  # Need at least symbol, price, and one more field
            return False
        
        # Check if first few cells contain stock-like data
        test_cells = [self._extract_text(col) for col in cols[:5]]
        
        # Look for patterns indicating this is a stock table
        has_symbol_pattern = any(
            len(text) <= 10 and text.isupper() and text.isalnum()
            for text in test_cells
        )
        
        has_price_pattern = any(
            self.parse_float(text) > 10  # Reasonable stock price threshold
            for text in test_cells
        )
        
        return has_symbol_pattern and has_price_pattern
    
    def _extract_stock_from_row(self, cols, column_map, source_name):
        """Extract stock data from a table row using column mapping"""
        try:
            # Extract symbol - try mapped position first, then scan first few columns
            symbol = ""
            if 'symbol' in column_map and column_map['symbol'] < len(cols):
                symbol = self._extract_text(cols[column_map['symbol']]).strip().upper()
            
            if not symbol:  # Fallback: scan first 3 columns for symbol-like text
                for i in range(min(3, len(cols))):
                    potential_symbol = self._extract_text(cols[i]).strip().upper()
                    if potential_symbol and len(potential_symbol) <= 10 and potential_symbol.isalnum():
                        symbol = potential_symbol
                        break
            
            if not symbol or len(symbol) > 10:
                return None
            
            # Extract LTP - try mapped position first, then scan for price-like values
            ltp = 0
            if 'ltp' in column_map and column_map['ltp'] < len(cols):
                ltp = self.parse_float(self._extract_text(cols[column_map['ltp']]))
            
            if ltp <= 0:  # Fallback: scan columns for price-like values
                for i in range(1, min(len(cols), 8)):  # Skip first column (likely symbol)
                    potential_price = self.parse_float(self._extract_text(cols[i]))
                    if potential_price > 10:  # Reasonable stock price threshold
                        ltp = potential_price
                        break
            
            if ltp <= 0:
                return None
            
            # Extract other fields with fallbacks
            company_name = symbol  # Default to symbol
            if 'company_name' in column_map and column_map['company_name'] < len(cols):
                company_name = self._extract_text(cols[column_map['company_name']])
                if not company_name:
                    company_name = symbol
            
            change = 0
            if 'change' in column_map and column_map['change'] < len(cols):
                change = self.parse_float(self._extract_text(cols[column_map['change']]))
            
            change_percent = 0
            if 'change_percent' in column_map and column_map['change_percent'] < len(cols):
                change_percent = self.parse_float(self._extract_text(cols[column_map['change_percent']]))
            elif change != 0 and ltp > 0:
                change_percent = (change / (ltp - change)) * 100 if (ltp - change) > 0 else 0
            
            high = ltp
            if 'high' in column_map and column_map['high'] < len(cols):
                high_val = self.parse_float(self._extract_text(cols[column_map['high']]))
                if high_val > 0:
                    high = high_val
            
            low = ltp
            if 'low' in column_map and column_map['low'] < len(cols):
                low_val = self.parse_float(self._extract_text(cols[column_map['low']]))
                if low_val > 0:
                    low = low_val
            
            open_price = ltp - change if change != 0 else ltp
            if 'open' in column_map and column_map['open'] < len(cols):
                open_val = self.parse_float(self._extract_text(cols[column_map['open']]))
                if open_val > 0:
                    open_price = open_val
            
            prev_close = ltp - change if change != 0 else ltp
            if 'prev_close' in column_map and column_map['prev_close'] < len(cols):
                prev_val = self.parse_float(self._extract_text(cols[column_map['prev_close']]))
                if prev_val > 0:
                    prev_close = prev_val
            
            qty = 0
            if 'qty' in column_map and column_map['qty'] < len(cols):
                qty = self.parse_int(self._extract_text(cols[column_map['qty']]))
            
            turnover = 0
            if 'turnover' in column_map and column_map['turnover'] < len(cols):
                turnover = self.parse_float(self._extract_text(cols[column_map['turnover']]))
            elif qty > 0 and ltp > 0:
                turnover = qty * ltp
            
            trades = 0
            if 'trades' in column_map and column_map['trades'] < len(cols):
                trades = self.parse_int(self._extract_text(cols[column_map['trades']]))
            
            return {
                'symbol': symbol,
                'company_name': company_name[:100],
                'ltp': ltp,
                'change': change,
                'change_percent': change_percent,
                'high': max(high, ltp) if high > 0 else ltp,
                'low': min(low, ltp) if low > 0 and low <= ltp else ltp,
                'open_price': open_price,
                'prev_close': prev_close,
                'qty': qty,
                'turnover': turnover,
                'trades': trades,
                'source': source_name
            }
            
        except Exception as e:
            logger.debug(f"Error extracting stock from row: {str(e)}")
            return None
    
    def scrape_stock_data(self, force=False, source_hint=None):
        """Enhanced stock data scraping with better error handling"""
        with self.scrape_lock:
            should_scrape, reason = self.should_scrape_now(force)
            if not should_scrape:
                logger.info(f"Skipping scrape: {reason}")
                return self.get_stock_count()
            
            logger.info(f"Starting stock data scraping: {reason}")
            
            all_stocks = []
            successful_source = None
            
            # Try each source
            sources_to_try = self.sources
            if source_hint:
                # Prioritize the hinted source
                sources_to_try = [s for s in self.sources if source_hint.lower() in s['name'].lower()] + \
                                [s for s in self.sources if source_hint.lower() not in s['name'].lower()]
            
            for source in sources_to_try:
                try:
                    logger.info(f"Trying source: {source['name']}")
                    
                    response = self.session.get(
                        source['url'], 
                        headers=self.headers, 
                        timeout=45, 
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        parser_method = getattr(self, source['parser'], None)
                        
                        if parser_method:
                            stocks = parser_method(soup, source)
                            
                            if stocks and len(stocks) > 10:  # Reasonable threshold
                                all_stocks = stocks
                                successful_source = source['name']
                                logger.info(f"Successfully scraped {len(stocks)} stocks from {source['name']}")
                                break
                            else:
                                logger.warning(f"Insufficient data from {source['name']}: {len(stocks) if stocks else 0} stocks")
                        else:
                            logger.error(f"Parser method {source['parser']} not found")
                    else:
                        logger.warning(f"HTTP {response.status_code} from {source['name']}")
                        
                except Exception as e:
                    logger.error(f"Error scraping {source['name']}: {str(e)}")
                    self._log_scrape_attempt(source['name'], 'failed', 0, str(e))
                    continue
            
            if all_stocks:
                count = self.save_stock_data(all_stocks, successful_source)
                self.last_scrape_time = datetime.now()
                self._log_scrape_attempt(successful_source, 'success', len(all_stocks))
                logger.info(f"Scraping completed successfully. {count} stocks updated from {successful_source}")
                return count
            else:
                logger.warning("All scraping sources failed, using sample data")
                self.populate_sample_data()
                return self.get_stock_count()
    
    def parse_sharesansar_live(self, soup, source):
        """Enhanced ShareSansar live trading parser with improved price detection"""
        stocks = []
        
        try:
            # Look for specific table containers first
            stock_containers = []
            
            # Try to find tables with specific classes or IDs
            specific_tables = soup.find_all('table', class_=re.compile(r'(stock|share|trading|market|live)', re.I))
            stock_containers.extend(specific_tables)
            
            # Try to find divs with stock data that contain tables
            stock_divs = soup.find_all('div', class_=re.compile(r'(live|trading|stock|market)', re.I))
            for div in stock_divs:
                tables = div.find_all('table')
                stock_containers.extend(tables)
            
            # Look for tables with specific IDs
            id_tables = soup.find_all('table', id=re.compile(r'(stock|share|trading|market|live)', re.I))
            stock_containers.extend(id_tables)
            
            # Fallback to all tables if specific ones not found
            if not stock_containers:
                stock_containers = soup.find_all('table')
            
            logger.debug(f"Found {len(stock_containers)} potential stock tables")
            
            for table in stock_containers:
                if not self._is_valid_stock_table(table):
                    continue
                
                # Get header row and map columns
                header_row = table.find('thead')
                if header_row:
                    header_row = header_row.find('tr')
                else:
                    header_row = table.find('tr')
                
                if not header_row:
                    continue
                
                header_cells = header_row.find_all(['th', 'td'])
                header_texts = [self._extract_text(cell) for cell in header_cells]
                column_map = self._map_columns(header_texts)
                
                logger.debug(f"Column mapping: {column_map}")
                
                # Process data rows
                data_rows = table.find_all('tr')[1:]  # Skip header
                table_stocks = []
                
                for row in data_rows:
                    cols = row.find_all(['td', 'th'])
                    
                    if len(cols) >= 3:
                        stock_data = self._extract_stock_from_row(cols, column_map, source['name'])
                        if stock_data:
                            table_stocks.append(stock_data)
                
                if table_stocks:
                    logger.info(f"Extracted {len(table_stocks)} stocks from table")
                    stocks.extend(table_stocks)
                    break  # Use first successful table
                    
        except Exception as e:
            logger.error(f"Error in parse_sharesansar_live: {str(e)}")
        
        return stocks
    
    def parse_sharesansar_today(self, soup, source):
        """Enhanced parser for ShareSansar today's prices"""
        stocks = []
        
        try:
            # Look for today's price tables
            price_containers = []
            
            # Look for specific containers
            today_divs = soup.find_all('div', class_=re.compile(r'(today|price|stock)', re.I))
            for div in today_divs:
                tables = div.find_all('table')
                price_containers.extend(tables)
            
            # Look for tables directly
            price_tables = soup.find_all('table', class_=re.compile(r'(price|stock|today)', re.I))
            price_containers.extend(price_tables)
            
            # Fallback to all tables
            if not price_containers:
                price_containers = soup.find_all('table')
            
            for table in price_containers:
                if not self._is_valid_stock_table(table):
                    continue
                
                # Get header and map columns
                header_row = table.find('thead')
                if header_row:
                    header_row = header_row.find('tr')
                else:
                    header_row = table.find('tr')
                
                if header_row:
                    header_cells = header_row.find_all(['th', 'td'])
                    header_texts = [self._extract_text(cell) for cell in header_cells]
                    column_map = self._map_columns(header_texts)
                else:
                    column_map = {}
                
                # Process data rows
                data_rows = table.find_all('tr')[1:] if header_row else table.find_all('tr')
                
                for row in data_rows:
                    cols = row.find_all(['td', 'th'])
                    
                    if len(cols) >= 3:
                        stock_data = self._extract_stock_from_row(cols, column_map, source['name'])
                        if stock_data:
                            stocks.append(stock_data)
                
                if stocks:
                    break  # Use first successful table
                    
        except Exception as e:
            logger.error(f"Error in parse_sharesansar_today: {str(e)}")
        
        return stocks
    
    def parse_merolagani(self, soup, source):
        """Enhanced MeroLagani parser"""
        stocks = []
        
        try:
            # Look for MeroLagani specific table structures
            market_containers = []
            
            # Look for specific containers
            market_divs = soup.find_all('div', class_=re.compile(r'(market|latest|stock)', re.I))
            for div in market_divs:
                tables = div.find_all('table')
                market_containers.extend(tables)
            
            # Look for tables with Bootstrap or common CSS classes
            bootstrap_tables = soup.find_all('table', class_=re.compile(r'(table|market|stock)', re.I))
            market_containers.extend(bootstrap_tables)
            
            # Fallback to all tables
            if not market_containers:
                market_containers = soup.find_all('table')
            
            for table in market_containers:
                if not self._is_valid_stock_table(table):
                    continue
                
                # MeroLagani typically has structured headers
                header_row = table.find('thead')
                if header_row:
                    header_row = header_row.find('tr')
                else:
                    rows = table.find_all('tr')
                    if rows:
                        header_row = rows[0]
                
                if header_row:
                    header_cells = header_row.find_all(['th', 'td'])
                    header_texts = [self._extract_text(cell) for cell in header_cells]
                    column_map = self._map_columns(header_texts)
                else:
                    # Default mapping for MeroLagani structure: S.N., Symbol, LTP, Change, %Change, High, Low
                    column_map = {
                        'symbol': 1,
                        'ltp': 2,
                        'change': 3,
                        'change_percent': 4,
                        'high': 5,
                        'low': 6
                    }
                
                # Process data rows
                data_rows = table.find_all('tr')[1:] if header_row else table.find_all('tr')
                
                for row in data_rows:
                    cols = row.find_all(['td', 'th'])
                    
                    if len(cols) >= 4:
                        stock_data = self._extract_stock_from_row(cols, column_map, source['name'])
                        if stock_data:
                            stocks.append(stock_data)
                
                if stocks:
                    break  # Use first successful table
                    
        except Exception as e:
            logger.error(f"Error in parse_merolagani: {str(e)}")
        
        return stocks
    
    def parse_nepse_official(self, soup, source):
        """Enhanced parser for NEPSE official website"""
        stocks = []
        
        try:
            # Look for NEPSE official data structures
            nepse_containers = []
            
            # Look for specific NEPSE containers
            nepse_divs = soup.find_all('div', class_=re.compile(r'(company|stock|market)', re.I))
            for div in nepse_divs:
                tables = div.find_all('table')
                nepse_containers.extend(tables)
            
            # Look for all tables as fallback
            if not nepse_containers:
                nepse_containers = soup.find_all('table')
            
            for table in nepse_containers:
                if not self._is_valid_stock_table(table):
                    continue
                
                # Get header and map columns
                header_row = table.find('thead')
                if header_row:
                    header_row = header_row.find('tr')
                else:
                    header_row = table.find('tr')
                
                if header_row:
                    header_cells = header_row.find_all(['th', 'td'])
                    header_texts = [self._extract_text(cell) for cell in header_cells]
                    column_map = self._map_columns(header_texts)
                else:
                    column_map = {}
                
                # Process data rows
                data_rows = table.find_all('tr')[1:] if header_row else table.find_all('tr')
                
                for row in data_rows:
                    cols = row.find_all(['td', 'th'])
                    
                    if len(cols) >= 2:
                        stock_data = self._extract_stock_from_row(cols, column_map, source['name'])
                        if stock_data:
                            stocks.append(stock_data)
                
                if stocks:
                    break  # Use first successful table
                    
        except Exception as e:
            logger.error(f"Error in parse_nepse_official: {str(e)}")
        
        return stocks
    
    def _extract_text(self, element):
        """Safely extract text from BeautifulSoup element"""
        if element is None:
            return ""
        return element.get_text(strip=True)
    
    def parse_float(self, value):
        """Enhanced float parsing with better number detection"""
        try:
            if not value:
                return 0.0
            
            # Convert to string and clean
            cleaned = str(value).replace(',', '').replace('Rs.', '').replace('NPR', '')
            cleaned = re.sub(r'[^\d.-]', '', cleaned)
            
            if not cleaned or cleaned == '-' or cleaned == '.':
                return 0.0
            
            # Handle multiple decimal points
            if cleaned.count('.') > 1:
                parts = cleaned.split('.')
                cleaned = parts[0] + '.' + ''.join(parts[1:])
            
            return float(cleaned)
        except (ValueError, AttributeError):
            return 0.0
    
    def parse_int(self, value):
        """Enhanced integer parsing"""
        try:
            if not value:
                return 0
            
            cleaned = str(value).replace(',', '')
            cleaned = re.sub(r'[^\d-]', '', cleaned)
            
            if not cleaned or cleaned == '-':
                return 0
            
            return int(cleaned)
        except (ValueError, AttributeError):
            return 0
    
    def save_stock_data(self, stocks, source_name):
        """Enhanced stock data saving with better data management"""
        if not stocks:
            return 0
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Mark all existing records as not latest
            cursor.execute('UPDATE stocks SET is_latest = FALSE')
            
            saved_count = 0
            for stock in stocks:
                try:
                    # Validate data
                    if not stock.get('symbol') or stock.get('ltp', 0) <= 0:
                        continue
                    
                    cursor.execute('''
                        INSERT INTO stocks 
                        (symbol, company_name, ltp, change, change_percent, high, low, 
                         open_price, prev_close, qty, turnover, trades, source, timestamp, is_latest)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE)
                    ''', (
                        stock['symbol'][:10],  # Limit symbol length
                        stock.get('company_name', stock['symbol'])[:100],  # Limit name length
                        stock['ltp'],
                        stock.get('change', 0),
                        stock.get('change_percent', 0),
                        stock.get('high', stock['ltp']),
                        stock.get('low', stock['ltp']),
                        stock.get('open_price', stock['ltp']),
                        stock.get('prev_close', stock['ltp']),
                        stock.get('qty', 0),
                        stock.get('turnover', 0),
                        stock.get('trades', 0),
                        source_name,
                        datetime.now()
                    ))
                    saved_count += 1
                    
                except Exception as e:
                    logger.debug(f"Error saving stock {stock.get('symbol', 'unknown')}: {str(e)}")
                    continue
            
            conn.commit()
            logger.info(f"Saved {saved_count}/{len(stocks)} stocks from {source_name}")
            return saved_count
            
        except Exception as e:
            logger.error(f"Error saving stock data: {str(e)}")
            conn.rollback()
            return 0
        finally:
            conn.close()
    
    def _log_scrape_attempt(self, source, status, stocks_found=0, error_message=None):
        """Log scraping attempts"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scrape_logs (source, status, stocks_found, error_message)
                VALUES (?, ?, ?, ?)
            ''', (source, status, stocks_found, error_message))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Failed to log scrape attempt: {e}")
    
    def populate_sample_data(self):
        """Enhanced sample data with more realistic prices"""
        logger.info("Populating enhanced sample stock data...")
        
        sample_stocks = [
            {'symbol': 'NABIL', 'company_name': 'NABIL BANK LIMITED', 'ltp': 1420.0, 'change': 15.0},
            {'symbol': 'ADBL', 'company_name': 'AGRICULTURE DEVELOPMENT BANK LIMITED', 'ltp': 350.0, 'change': -5.0},
            {'symbol': 'EBL', 'company_name': 'EVEREST BANK LIMITED', 'ltp': 720.0, 'change': 12.0},
            {'symbol': 'NBL', 'company_name': 'NEPAL BANK LIMITED', 'ltp': 410.0, 'change': -8.0},
            {'symbol': 'SBI', 'company_name': 'NEPAL SBI BANK LIMITED', 'ltp': 460.0, 'change': 7.0},
            {'symbol': 'KBL', 'company_name': 'KUMARI BANK LIMITED', 'ltp': 310.0, 'change': -3.0},
            {'symbol': 'HBL', 'company_name': 'HIMALAYAN BANK LIMITED', 'ltp': 560.0, 'change': 10.0},
            {'symbol': 'HIDCL', 'company_name': 'HYDROELECTRICITY INVESTMENT AND DEVELOPMENT COMPANY LIMITED', 'ltp': 305.0, 'change': 2.0},
            {'symbol': 'NFS', 'company_name': 'NEPAL FINANCE LTD', 'ltp': 790.0, 'change': 18.0},
            {'symbol': 'CORBL', 'company_name': 'CORPORATE DEVELOPMENT BANK LIMITED', 'ltp': 2250.0, 'change': -25.0},
            {'symbol': 'GBIME', 'company_name': 'GLOBAL IME BANK LIMITED', 'ltp': 395.0, 'change': 5.0},
            {'symbol': 'SANIMA', 'company_name': 'SANIMA BANK LIMITED', 'ltp': 348.0, 'change': -2.0},
            {'symbol': 'MBL', 'company_name': 'MACHHAPUCHCHHRE BANK LIMITED', 'ltp': 425.0, 'change': 8.0},
            {'symbol': 'PCBL', 'company_name': 'PRIME COMMERCIAL BANK LIMITED', 'ltp': 495.0, 'change': -7.0},
            {'symbol': 'SCB', 'company_name': 'STANDARD CHARTERED BANK NEPAL LIMITED', 'ltp': 634.0, 'change': 12.0},
        ]
        
        enriched_stocks = []
        for stock in sample_stocks:
            base_price = stock['ltp']
            change = stock['change']
            high = base_price + abs(change) + 5
            low = base_price - abs(change) - 5
            
            enriched_stocks.append({
                'symbol': stock['symbol'],
                'company_name': stock['company_name'],
                'ltp': base_price,
                'change': change,
                'change_percent': (change / base_price) * 100,
                'high': high,
                'low': low,
                'open_price': base_price - change,
                'prev_close': base_price - change,
                'qty': abs(hash(stock['symbol'])) % 5000 + 1000,
                'turnover': base_price * (abs(hash(stock['symbol'])) % 5000 + 1000),
                'trades': abs(hash(stock['symbol'])) % 100 + 20,
                'source': 'Sample Data'
            })
        
        self.save_stock_data(enriched_stocks, 'Sample Data')
        self.last_scrape_time = datetime.now()
    
    def get_stock_count(self):
        """Get total number of unique stocks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT COUNT(DISTINCT symbol) FROM stocks WHERE is_latest = TRUE')
            count = cursor.fetchone()[0]
            return count
        except:
            return 0
        finally:
            conn.close()
    
    def get_latest_data(self, symbol=None):
        """Get latest stock data with enhanced fields"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if symbol:
                cursor.execute('''
                    SELECT symbol, company_name, ltp, change, change_percent, 
                           high, low, open_price, prev_close, qty, turnover, 
                           trades, source, timestamp
                    FROM stocks 
                    WHERE symbol = ? AND is_latest = TRUE 
                    ORDER BY timestamp DESC 
                    LIMIT 1
                ''', (symbol.upper(),))
            else:
                cursor.execute('''
                    SELECT symbol, company_name, ltp, change, change_percent, 
                           high, low, open_price, prev_close, qty, turnover, 
                           trades, source, timestamp
                    FROM stocks 
                    WHERE is_latest = TRUE
                    ORDER BY symbol
                ''')
            
            columns = ['symbol', 'company_name', 'ltp', 'change', 'change_percent', 
                      'high', 'low', 'open_price', 'prev_close', 'qty', 'turnover', 
                      'trades', 'source', 'timestamp']
            results = []
            
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            return results
        finally:
            conn.close()
    
    def run_initial_scrape(self):
        """Run initial scrape on startup"""
        logger.info("Running initial stock data scrape on startup...")
        try:
            count = self.scrape_stock_data(force=True)  # Force initial scrape
            logger.info(f"Initial scrape completed. {count} stocks available.")
            return count
        except Exception as e:
            logger.error(f"Initial scrape failed: {str(e)}")
            self.populate_sample_data()
            return self.get_stock_count()
    
    def start_smart_scheduler(self):
        """Start intelligent scheduler that respects market hours"""
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            logger.warning("Scheduler already running")
            return
        
        def smart_scheduler():
            logger.info("Smart scheduler started - will scrape every 30 minutes during market hours")
            
            while not self.should_stop_scheduler:
                try:
                    # Check if we should scrape now
                    should_scrape, reason = self.should_scrape_now()
                    
                    if should_scrape:
                        logger.info(f"Scheduled scrape triggered: {reason}")
                        self.scrape_stock_data()
                        # Sleep for 30 minutes after successful scrape
                        sleep_time = 1800  # 30 minutes
                    else:
                        # Check again in 5 minutes if not scraping
                        sleep_time = 300  # 5 minutes
                        logger.debug(f"Scheduler waiting: {reason}")
                    
                    # Sleep in small chunks so we can respond to stop signal
                    for _ in range(sleep_time // 30):
                        if self.should_stop_scheduler:
                            break
                        time_module.sleep(30)
                        
                except Exception as e:
                    logger.error(f"Scheduler error: {str(e)}")
                    time_module.sleep(300)  # Wait 5 minutes on error
            
            logger.info("Smart scheduler stopped")
        
        self.should_stop_scheduler = False
        self.scheduler_thread = threading.Thread(target=smart_scheduler, daemon=True)
        self.scheduler_thread.start()
    
    def stop_scheduler(self):
        """Stop the scheduler"""
        self.should_stop_scheduler = True
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
    
    def get_market_status(self):
        """Get current market status"""
        return self.market_hours.get_market_status()
    
    def get_scrape_logs(self, limit=10):
        """Get recent scrape logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT timestamp, source, status, stocks_found, error_message
                FROM scrape_logs
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            columns = ['timestamp', 'source', 'status', 'stocks_found', 'error_message']
            results = []
            
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            return results
        finally:
            conn.close()

# Flask API with Enhanced Market Hours Support
app = Flask(__name__)
CORS(app)

# Initialize scraper
logger.info("Initializing Enhanced Nepal Stock Scraper...")
scraper = NepalStockScraper()

# Run initial scrape
logger.info("Running initial data population...")
initial_count = scraper.run_initial_scrape()
logger.info(f"Initial data population complete. {initial_count} stocks loaded.")

# Start smart scheduler
scraper.start_smart_scheduler()

# Initialize security manager
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

# Enhanced API Routes

@app.route('/api/health', methods=['GET'])
def health_check():
    """Enhanced health check with market status"""
    stock_count = scraper.get_stock_count()
    market_status = scraper.get_market_status()
    
    return jsonify({
        'success': True,
        'status': 'healthy',
        'stock_count': stock_count,
        'market_status': market_status,
        'last_scrape': scraper.last_scrape_time.isoformat() if scraper.last_scrape_time else None,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/market-status', methods=['GET'])
def get_market_status():
    """Get detailed market status"""
    try:
        market_status = scraper.get_market_status()
        return jsonify({
            'success': True,
            'market_status': market_status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stocks', methods=['GET'])
@require_auth
def get_stocks():
    """Enhanced API endpoint to get all latest stock data"""
    try:
        symbol = request.args.get('symbol')
        data = scraper.get_latest_data(symbol)
        market_status = scraper.get_market_status()
        
        return jsonify({
            'success': True,
            'data': data,
            'count': len(data),
            'market_status': market_status,
            'last_scrape': scraper.last_scrape_time.isoformat() if scraper.last_scrape_time else None,
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
    """Enhanced API endpoint to get specific stock data"""
    try:
        data = scraper.get_latest_data(symbol.upper())
        if data:
            return jsonify({
                'success': True,
                'data': data[0],
                'market_status': scraper.get_market_status(),
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
    """Enhanced manual trigger for scraping with market hours check"""
    try:
        force = request.json.get('force', False) if request.is_json else False
        source_hint = request.json.get('source', None) if request.is_json else None
        
        market_status = scraper.get_market_status()
        
        # Allow forced scrapes or scrapes during/near market hours
        if not force and market_status['status'] not in ['open', 'pre_market', 'after_hours']:
            return jsonify({
                'success': False,
                'error': f"Market is {market_status['status']}. Use force=true to override.",
                'market_status': market_status
            }), 400
        
        logger.info(f"Manual scrape triggered by {request.key_info['key_id']} (force={force})")
        count = scraper.scrape_stock_data(force=True, source_hint=source_hint)
        
        return jsonify({
            'success': True,
            'message': f'Scraping completed successfully. {count} stocks updated.',
            'count': count,
            'market_status': market_status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Manual scrape failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/scrape-logs', methods=['GET'])
@require_auth
def get_scrape_logs():
    """Get recent scraping logs"""
    try:
        limit = min(int(request.args.get('limit', 10)), 50)  # Max 50 logs
        logs = scraper.get_scrape_logs(limit)
        
        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs)
        })
    except Exception as e:
        logger.error(f"Error getting scrape logs: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/key-info', methods=['GET'])
@require_auth
def get_key_info():
    """Get information about the authenticated key"""
    try:
        key_info = security_manager.get_key_info(request.key_info['key_id'])
        if key_info:
            return jsonify({
                'success': True,
                'key_info': key_info
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Key information not found'
            }), 404
    except Exception as e:
        logger.error(f"Error getting key info: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Admin endpoints
@app.route('/api/admin/generate-key', methods=['POST'])
@require_auth
@require_admin
def admin_generate_key():
    """Generate new API key (admin only)"""
    try:
        data = request.get_json()
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
        logger.error(f"Error generating key: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/admin/keys', methods=['GET'])
@require_auth
@require_admin
def admin_list_keys():
    """List all API keys (admin only)"""
    try:
        keys = security_manager.list_all_keys()
        return jsonify({
            'success': True,
            'keys': keys
        })
    except Exception as e:
        logger.error(f"Error listing keys: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/admin/keys/<key_id>/delete', methods=['DELETE'])
@require_auth
@require_admin
def admin_delete_key(key_id):
    """Delete an API key (admin only)"""
    try:
        if key_id == request.key_info['key_id']:
            return jsonify({
                'success': False,
                'error': 'Cannot delete your own admin key'
            }), 400
        
        success = security_manager.delete_key(key_id)
        if success:
            return jsonify({
                'success': True,
                'message': f'Key {key_id} deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Key not found or failed to delete'
            }), 404
    except Exception as e:
        logger.error(f"Error deleting key: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/admin/stats', methods=['GET'])
@require_auth
@require_admin
def admin_stats():
    """Get enhanced system statistics (admin only)"""
    try:
        conn = sqlite3.connect(scraper.db_path)
        cursor = conn.cursor()
        
        # Get key statistics
        cursor.execute('SELECT COUNT(*) FROM api_keys WHERE is_active = TRUE')
        active_keys = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM api_keys')
        total_keys = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM device_sessions WHERE is_active = TRUE')
        active_sessions = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM api_logs WHERE timestamp > datetime("now", "-24 hours")')
        requests_24h = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scrape_logs WHERE timestamp > datetime("now", "-24 hours")')
        scrapes_24h = cursor.fetchone()[0]
        
        stock_count = scraper.get_stock_count()
        market_status = scraper.get_market_status()
        
        conn.close()
        
        return jsonify({
            'success': True,
            'stats': {
                'active_keys': active_keys,
                'total_keys': total_keys,
                'active_sessions': active_sessions,
                'requests_24h': requests_24h,
                'scrapes_24h': scrapes_24h,
                'stock_count': stock_count,
                'market_status': market_status,
                'last_scrape': scraper.last_scrape_time.isoformat() if scraper.last_scrape_time else None,
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
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
    logger.info(f"Starting enhanced secured Flask app on port {port}")
    logger.info(f"Stock database contains {scraper.get_stock_count()} stocks")
    logger.info(f"Market status: {scraper.get_market_status()}")
    app.run(host='0.0.0.0', port=port, debug=False)