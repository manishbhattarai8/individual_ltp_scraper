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

class NepalStockScraper:
    def __init__(self, db_path='nepal_stock.db'):
        self.db_path = db_path
        self.market_hours = MarketHours()
        
        # Simplified source list - focusing on what works
        self.urls = [
            'https://www.sharesansar.com/live-trading',
            'https://www.sharesansar.com/today-share-price',
            'https://merolagani.com/LatestMarket.aspx'
        ]
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Configure session
        self.session = requests.Session()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Scraping control
        self.last_scrape_time = None
        self.scrape_lock = threading.Lock()
        
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
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    def scrape_stock_data(self, force=False):
        """Main scraping method - simplified and reliable"""
        with self.scrape_lock:
            logger.info("Starting stock data scraping...")
            
            all_stocks = []
            successful_source = None
            
            for url in self.urls:
                try:
                    logger.info(f"Trying source: {url}")
                    
                    # Try with SSL verification first, then without
                    for verify_ssl in [True, False]:
                        try:
                            response = self.session.get(
                                url, 
                                headers=self.headers, 
                                timeout=30,
                                verify=verify_ssl
                            )
                            response.raise_for_status()
                            
                            if response.status_code == 200 and len(response.content) > 1000:
                                logger.info(f"Successfully fetched data from {url}")
                                
                                # Parse based on URL
                                if 'sharesansar.com' in url:
                                    stocks = self.parse_sharesansar_simple(response.content, url)
                                elif 'merolagani.com' in url:
                                    stocks = self.parse_merolagani_simple(response.content, url)
                                else:
                                    stocks = self.parse_generic_simple(response.content, url)
                                
                                if stocks and len(stocks) > 50:  # Reasonable threshold
                                    all_stocks = stocks
                                    successful_source = url
                                    logger.info(f"Successfully parsed {len(stocks)} stocks from {url}")
                                    break
                                else:
                                    logger.warning(f"Insufficient data from {url}: {len(stocks) if stocks else 0} stocks")
                            
                            break  # Break verify_ssl loop if successful
                            
                        except requests.exceptions.SSLError:
                            if verify_ssl:
                                logger.warning(f"SSL error for {url}, trying without SSL verification")
                                continue
                            else:
                                logger.error(f"SSL error even without verification for {url}")
                                break
                        except Exception as e:
                            logger.warning(f"Error with {url} (SSL verify: {verify_ssl}): {e}")
                            break
                    
                    if all_stocks:  # If we got data, stop trying other sources
                        break
                        
                except Exception as e:
                    logger.error(f"Error scraping {url}: {str(e)}")
                    continue
            
            if all_stocks:
                count = self.save_stock_data(all_stocks, successful_source)
                self.last_scrape_time = datetime.now()
                logger.info(f"Scraping completed successfully. {count} stocks updated from {successful_source}")
                return count
            else:
                logger.warning("All scraping sources failed, using sample data")
                self.populate_sample_data()
                return self.get_stock_count()
    
    def parse_sharesansar_simple(self, content, url):
        """Simplified ShareSansar parser focused on reliability"""
        soup = BeautifulSoup(content, 'html.parser')
        stocks_data = []
        
        try:
            # Method 1: Look for tables with stock data
            tables = soup.find_all('table')
            
            for table in tables:
                rows = table.find_all('tr')
                if len(rows) < 10:  # Skip small tables
                    continue
                
                # Check if this looks like a stock table
                header_row = rows[0] if rows else None
                if not header_row:
                    continue
                
                header_text = header_row.get_text().lower()
                if not any(keyword in header_text for keyword in ['symbol', 'ltp', 'price', 'change']):
                    continue
                
                logger.info("Found potential stock table in ShareSansar")
                
                # Simple column detection
                header_cells = header_row.find_all(['th', 'td'])
                headers = [cell.get_text(strip=True).lower() for cell in header_cells]
                
                # Find column indices
                symbol_idx = self.find_column_index(headers, ['symbol', 'stock', 'scrip'])
                ltp_idx = self.find_column_index(headers, ['ltp', 'price', 'last'])
                change_idx = self.find_column_index(headers, ['change', 'diff'])
                qty_idx = self.find_column_index(headers, ['qty', 'volume'])
                
                if symbol_idx < 0 or ltp_idx < 0:
                    continue
                
                # Parse data rows
                for row in rows[1:]:
                    cols = row.find_all(['td', 'th'])
                    if len(cols) <= max(symbol_idx, ltp_idx):
                        continue
                    
                    try:
                        # Extract symbol
                        symbol_text = cols[symbol_idx].get_text(strip=True)
                        symbol = re.sub(r'[^\w]', '', symbol_text).upper()
                        
                        if not self.is_valid_symbol(symbol):
                            continue
                        
                        # Extract LTP
                        ltp_text = cols[ltp_idx].get_text(strip=True)
                        ltp = self.safe_float(ltp_text)
                        
                        if not self.is_valid_price(ltp):
                            continue
                        
                        # Extract change
                        change = 0.0
                        if change_idx >= 0 and len(cols) > change_idx:
                            change = self.safe_float(cols[change_idx].get_text(strip=True))
                        
                        # Extract quantity
                        qty = 1000
                        if qty_idx >= 0 and len(cols) > qty_idx:
                            qty = self.safe_int(cols[qty_idx].get_text(strip=True))
                            if qty <= 0:
                                qty = 1000
                        
                        # Calculate derived values
                        change_percent = (change / ltp * 100) if ltp > 0 else 0.0
                        prev_close = ltp - change if change != 0 else ltp
                        
                        stock_data = {
                            'symbol': symbol,
                            'company_name': symbol,
                            'ltp': ltp,
                            'change': change,
                            'change_percent': change_percent,
                            'high': ltp + abs(change) if change > 0 else ltp,
                            'low': ltp - abs(change) if change < 0 else ltp,
                            'open_price': prev_close,
                            'prev_close': prev_close,
                            'qty': qty,
                            'turnover': ltp * qty,
                            'trades': 0,
                            'source': url
                        }
                        
                        stocks_data.append(stock_data)
                        
                    except Exception as e:
                        logger.debug(f"Error parsing row: {e}")
                        continue
                
                if stocks_data:
                    logger.info(f"ShareSansar parsing found {len(stocks_data)} stocks")
                    return stocks_data
        
        except Exception as e:
            logger.error(f"Error in ShareSansar parsing: {e}")
        
        return stocks_data
    
    def parse_merolagani_simple(self, content, url):
        """Simplified MeroLagani parser"""
        soup = BeautifulSoup(content, 'html.parser')
        stocks_data = []
        
        try:
            # Look for main market data table
            table = soup.find('table', {'id': 'headtable'}) or soup.find('table', class_='table')
            
            if not table:
                # Try all tables
                tables = soup.find_all('table')
                for t in tables:
                    rows = t.find_all('tr')
                    if len(rows) > 20:  # Large table likely to be stock data
                        table = t
                        break
            
            if table:
                rows = table.find_all('tr')
                if len(rows) < 2:
                    return stocks_data
                
                # Skip header row
                for row in rows[1:]:
                    cols = row.find_all('td')
                    if len(cols) < 3:
                        continue
                    
                    try:
                        # Basic parsing - adjust indices based on MeroLagani structure
                        symbol = self.clean_symbol(cols[1].get_text(strip=True)) if len(cols) > 1 else self.clean_symbol(cols[0].get_text(strip=True))
                        ltp = self.safe_float(cols[2].get_text(strip=True)) if len(cols) > 2 else 0
                        change = self.safe_float(cols[3].get_text(strip=True)) if len(cols) > 3 else 0
                        
                        if not self.is_valid_symbol(symbol) or not self.is_valid_price(ltp):
                            continue
                        
                        change_percent = (change / ltp * 100) if ltp > 0 else 0.0
                        
                        stock_data = {
                            'symbol': symbol,
                            'company_name': symbol,
                            'ltp': ltp,
                            'change': change,
                            'change_percent': change_percent,
                            'high': ltp * 1.02,
                            'low': ltp * 0.98,
                            'open_price': ltp - change,
                            'prev_close': ltp - change,
                            'qty': 1000,
                            'turnover': ltp * 1000,
                            'trades': 0,
                            'source': url
                        }
                        stocks_data.append(stock_data)
                        
                    except Exception as e:
                        continue
        
        except Exception as e:
            logger.error(f"Error in MeroLagani parsing: {e}")
        
        return stocks_data
    
    def parse_generic_simple(self, content, url):
        """Simplified generic parser"""
        soup = BeautifulSoup(content, 'html.parser')
        stocks_data = []
        
        try:
            tables = soup.find_all('table')
            
            for table in tables:
                rows = table.find_all('tr')
                if len(rows) < 10:
                    continue
                
                header_row = rows[0]
                headers = [th.get_text(strip=True).lower() for th in header_row.find_all(['th', 'td'])]
                
                symbol_idx = self.find_column_index(headers, ['symbol', 'stock', 'scrip'])
                ltp_idx = self.find_column_index(headers, ['ltp', 'price', 'last', 'current'])
                change_idx = self.find_column_index(headers, ['change', 'diff'])
                
                if symbol_idx < 0 or ltp_idx < 0:
                    continue
                
                for row in rows[1:]:
                    cols = row.find_all(['td', 'th'])
                    if len(cols) <= max(symbol_idx, ltp_idx):
                        continue
                    
                    try:
                        symbol = self.clean_symbol(cols[symbol_idx].get_text(strip=True))
                        ltp = self.safe_float(cols[ltp_idx].get_text(strip=True))
                        
                        if not self.is_valid_symbol(symbol) or not self.is_valid_price(ltp):
                            continue
                        
                        change = 0.0
                        if change_idx >= 0 and len(cols) > change_idx:
                            change = self.safe_float(cols[change_idx].get_text(strip=True))
                        
                        stock_data = {
                            'symbol': symbol,
                            'company_name': symbol,
                            'ltp': ltp,
                            'change': change,
                            'change_percent': (change/ltp*100) if ltp > 0 else 0.0,
                            'high': ltp,
                            'low': ltp,
                            'open_price': ltp - change,
                            'prev_close': ltp - change,
                            'qty': 1000,
                            'turnover': ltp * 1000,
                            'trades': 0,
                            'source': url
                        }
                        stocks_data.append(stock_data)
                        
                    except Exception as e:
                        continue
                
                if stocks_data:
                    break
        
        except Exception as e:
            logger.error(f"Error in generic parsing: {e}")
        
        return stocks_data
    
    def find_column_index(self, headers, possible_names):
        """Find column index by matching possible column names"""
        for i, header in enumerate(headers):
            for name in possible_names:
                if name in header:
                    return i
        return -1
    
    def clean_symbol(self, symbol_text):
        """Clean and validate symbol text"""
        if not symbol_text:
            return ""
        return re.sub(r'[^\w]', '', symbol_text).upper()
    
    def is_valid_symbol(self, symbol):
        """Check if symbol is valid"""
        if not symbol or len(symbol) < 2 or len(symbol) > 10:
            return False
        if symbol.isdigit():
            return False
        # Exclude obvious non-symbols
        invalid_symbols = ['NO', 'SN', 'SR', 'NAME', 'PRICE', 'CHANGE', 'HIGH', 'LOW', 'QTY', 'VOLUME']
        return symbol not in invalid_symbols
    
    def is_valid_price(self, price):
        """Check if price is reasonable for Nepal stock"""
        return 10 <= price <= 5000 if price > 0 else False
    
    def safe_float(self, value):
        """Safely convert string to float"""
        try:
            if value is None:
                return 0.0
            # Remove commas, percentage signs, and other non-numeric characters
            cleaned_value = str(value).replace(',', '').replace('%', '').replace('Rs.', '').replace('NPR', '').strip()
            # Handle negative values in parentheses
            if cleaned_value.startswith('(') and cleaned_value.endswith(')'):
                cleaned_value = '-' + cleaned_value[1:-1]
            return float(cleaned_value) if cleaned_value and cleaned_value != '-' else 0.0
        except:
            return 0.0
    
    def safe_int(self, value):
        """Safely convert string to int"""
        try:
            if value is None:
                return 0
            cleaned_value = str(value).replace(',', '').strip()
            return int(float(cleaned_value)) if cleaned_value and cleaned_value != '-' else 0
        except:
            return 0
    
    def populate_sample_data(self):
        """Populate sample data when scraping fails"""
        logger.info("Populating sample stock data...")
        
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
    
    def save_stock_data(self, stocks, source_name):
        """Save stock data to database"""
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
                        stock['symbol'][:10],
                        stock.get('company_name', stock['symbol'])[:100],
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
        """Get latest stock data"""
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
            count = self.scrape_stock_data(force=True)
            logger.info(f"Initial scrape completed. {count} stocks available.")
            return count
        except Exception as e:
            logger.error(f"Initial scrape failed: {str(e)}")
            self.populate_sample_data()
            return self.get_stock_count()
    
    def get_market_status(self):
        """Get current market status"""
        return self.market_hours.get_market_status()

# Flask API
app = Flask(__name__)
CORS(app)

# Initialize scraper
logger.info("Initializing Fixed Nepal Stock Scraper...")
scraper = NepalStockScraper()

# Run initial scrape
logger.info("Running initial data population...")
initial_count = scraper.run_initial_scrape()
logger.info(f"Initial data population complete. {initial_count} stocks loaded.")

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

# API Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check with market status"""
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
    """Get all latest stock data"""
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
    """Get specific stock data"""
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
    """Manual trigger for scraping"""
    try:
        force = request.json.get('force', False) if request.is_json else False
        
        logger.info(f"Manual scrape triggered by {request.key_info['key_id']} (force={force})")
        count = scraper.scrape_stock_data(force=True)
        
        return jsonify({
            'success': True,
            'message': f'Scraping completed successfully. {count} stocks updated.',
            'count': count,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Manual scrape failed: {e}")
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
    logger.info(f"Starting fixed secured Flask app on port {port}")
    logger.info(f"Stock database contains {scraper.get_stock_count()} stocks")
    logger.info(f"Market status: {scraper.get_market_status()}")
    app.run(host='0.0.0.0', port=port, debug=False)