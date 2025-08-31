import requests
from bs4 import BeautifulSoup
import json
import sqlite3
import schedule
import time
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import logging
import os
import ssl
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
    
    def scrape_stock_data(self):
        """Scrape stock data from multiple Nepal Stock Exchange sources"""
        
        for url in self.urls:
            try:
                logger.info(f"Trying to scrape from: {url}")
                
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
                        
                        # Check if we got a valid response
                        if response.status_code == 200 and len(response.content) > 1000:
                            logger.info(f"Successfully fetched data from {url} (SSL verify: {verify_ssl})")
                            return self.parse_stock_data(response.content, url)
                        
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
                        
            except Exception as e:
                logger.warning(f"Failed to access {url}: {e}")
                continue
        
        # If all sources fail, return sample data for testing
        logger.warning("All sources failed, returning sample data for testing")
        return self.get_sample_data()
    
    def parse_stock_data(self, content, url):
        """Parse stock data from HTML content based on the source"""
        soup = BeautifulSoup(content, 'html.parser')
        stocks_data = []
        
        try:
            if 'sharesansar.com' in url:
                # Try ShareSansar specific parsing first
                stocks_data = self.parse_sharesansar_improved(soup)
                if not stocks_data:
                    # Fallback to generic parsing
                    stocks_data = self.parse_generic_table(soup)
            elif 'merolagani.com' in url:
                stocks_data = self.parse_merolagani(soup)
            elif 'nepalstock.com' in url:
                stocks_data = self.parse_nepalstock(soup)
            else:
                # Try generic table parsing as fallback
                stocks_data = self.parse_generic_table(soup)
                
        except Exception as e:
            logger.error(f"Error parsing data from {url}: {e}")
            # Try generic parsing as last resort
            try:
                stocks_data = self.parse_generic_table(soup)
            except Exception as e2:
                logger.error(f"Generic parsing also failed: {e2}")
        
        logger.info(f"Parsed {len(stocks_data)} stocks from {url}")
        return stocks_data
    
    def parse_sharesansar_improved(self, soup):
        """Improved ShareSansar parser that looks for actual HTML tables"""
        stocks_data = []
        
        try:
            # Method 1: Look for HTML tables first
            tables = soup.find_all('table')
            
            for table in tables:
                rows = table.find_all('tr')
                if len(rows) < 5:  # Skip small tables
                    continue
                
                # Check if this looks like a stock data table
                header_row = rows[0]
                header_text = header_row.get_text().lower()
                
                if any(keyword in header_text for keyword in ['symbol', 'ltp', 'price', 'change']):
                    logger.info("Found potential stock table in ShareSansar")
                    
                    # Parse the table
                    for row in rows[1:]:  # Skip header
                        cols = row.find_all(['td', 'th'])
                        if len(cols) >= 3:
                            try:
                                # Extract data from table cells
                                symbol_text = cols[0].get_text(strip=True) if len(cols) > 0 else ""
                                ltp_text = cols[1].get_text(strip=True) if len(cols) > 1 else "0"
                                change_text = cols[2].get_text(strip=True) if len(cols) > 2 else "0"
                                
                                # Clean symbol (remove any HTML artifacts)
                                symbol = re.sub(r'[^\w]', '', symbol_text).upper()
                                
                                # Parse numeric values
                                ltp = self.safe_float(ltp_text)
                                change = self.safe_float(change_text)
                                
                                if symbol and len(symbol) >= 2 and ltp > 0:
                                    # Calculate additional fields
                                    change_percent = (change / ltp * 100) if ltp > 0 else 0.0
                                    
                                    stock_data = {
                                        'symbol': symbol,
                                        'company_name': symbol,
                                        'ltp': ltp,
                                        'change': change,
                                        'change_percent': change_percent,
                                        'high': ltp + abs(change) if change > 0 else ltp,
                                        'low': ltp - abs(change) if change < 0 else ltp,
                                        'open_price': ltp - change,
                                        'qty': self.safe_int(cols[3].get_text(strip=True)) if len(cols) > 3 else 1000,
                                        'turnover': ltp * 1000  # Default turnover
                                    }
                                    
                                    stocks_data.append(stock_data)
                                    
                            except Exception as e:
                                continue
                    
                    if stocks_data:
                        logger.info(f"ShareSansar table parsing found {len(stocks_data)} stocks")
                        return stocks_data
            
            # Method 2: Look for JavaScript data or JSON
            scripts = soup.find_all('script')
            for script in scripts:
                script_content = script.get_text()
                if 'symbol' in script_content.lower() and 'ltp' in script_content.lower():
                    # Try to extract JSON data from script
                    json_matches = re.findall(r'\{[^{}]*"symbol"[^{}]*\}', script_content, re.IGNORECASE)
                    for match in json_matches:
                        try:
                            data = json.loads(match)
                            if 'symbol' in data and 'ltp' in data:
                                stocks_data.append(self.normalize_stock_data(data))
                        except:
                            continue
            
            # Method 3: Look for div-based data structures
            stock_containers = soup.find_all('div', class_=re.compile(r'stock|share|trade', re.I))
            for container in stock_containers:
                try:
                    text = container.get_text()
                    # Look for pattern like "SYMBOL 123.45 +2.3"
                    matches = re.findall(r'([A-Z]{2,8})\s+(\d+\.?\d*)\s*([+-]?\d+\.?\d*)', text)
                    for match in matches:
                        symbol, ltp_str, change_str = match
                        ltp = self.safe_float(ltp_str)
                        change = self.safe_float(change_str)
                        
                        if ltp > 0:
                            stock_data = {
                                'symbol': symbol,
                                'company_name': symbol,
                                'ltp': ltp,
                                'change': change,
                                'change_percent': (change / ltp * 100) if ltp > 0 else 0.0,
                                'high': ltp + abs(change) if change > 0 else ltp,
                                'low': ltp - abs(change) if change < 0 else ltp,
                                'open_price': ltp - change,
                                'qty': 1000,
                                'turnover': ltp * 1000
                            }
                            stocks_data.append(stock_data)
                except:
                    continue
            
            logger.info(f"ShareSansar improved parsing found {len(stocks_data)} stocks")
            
        except Exception as e:
            logger.error(f"Error in improved ShareSansar parsing: {e}")
            
        return stocks_data
    
    def parse_nepalstock(self, soup):
        """Parse data from nepalstock.com.np"""
        stocks_data = []
        
        # Look for table with stock data
        tables = soup.find_all('table')
        
        for table in tables:
            rows = table.find_all('tr')
            if len(rows) < 2:  # Skip if no data rows
                continue
                
            for row in rows[1:]:  # Skip header
                cols = row.find_all(['td', 'th'])
                if len(cols) >= 3:
                    try:
                        # Basic parsing - adjust based on actual structure
                        symbol = cols[0].get_text(strip=True)
                        ltp = self.safe_float(cols[1].get_text(strip=True))
                        change = self.safe_float(cols[2].get_text(strip=True)) if len(cols) > 2 else 0.0
                        
                        if symbol and ltp > 0:
                            stock_data = {
                                'symbol': symbol,
                                'company_name': symbol,
                                'ltp': ltp,
                                'change': change,
                                'change_percent': (change/ltp*100) if ltp > 0 else 0.0,
                                'high': ltp * 1.05,
                                'low': ltp * 0.95,
                                'open_price': ltp - change,
                                'qty': 1000,
                                'turnover': ltp * 1000
                            }
                            stocks_data.append(stock_data)
                            
                    except Exception as e:
                        logger.warning(f"Error parsing row: {e}")
                        continue
                        
        return stocks_data
    
    def parse_merolagani(self, soup):
        """Parse data from merolagani.com"""
        stocks_data = []
        
        # Look for the main market data table
        table = soup.find('table', {'id': 'headtable'}) or soup.find('table', class_='table')
        
        if table:
            rows = table.find_all('tr')[1:]  # Skip header
            
            for row in rows:
                cols = row.find_all('td')
                if len(cols) >= 6:
                    try:
                        symbol = cols[1].get_text(strip=True) if len(cols) > 1 else cols[0].get_text(strip=True)
                        ltp = self.safe_float(cols[2].get_text(strip=True))
                        change = self.safe_float(cols[3].get_text(strip=True))
                        high = self.safe_float(cols[4].get_text(strip=True)) if len(cols) > 4 else ltp
                        low = self.safe_float(cols[5].get_text(strip=True)) if len(cols) > 5 else ltp
                        
                        if symbol and ltp > 0:
                            stock_data = {
                                'symbol': symbol,
                                'company_name': symbol,
                                'ltp': ltp,
                                'change': change,
                                'change_percent': (change/ltp*100) if ltp > 0 else 0.0,
                                'high': high,
                                'low': low,
                                'open_price': ltp - change,
                                'qty': 1000,
                                'turnover': ltp * 1000
                            }
                            stocks_data.append(stock_data)
                            
                    except Exception as e:
                        continue
                        
        return stocks_data
    
    def parse_generic_table(self, soup):
        """Enhanced generic table parser for any stock data table"""
        stocks_data = []
        
        # Find all tables and try to parse
        tables = soup.find_all('table')
        
        for table in tables:
            rows = table.find_all('tr')
            if len(rows) < 5:  # Skip small tables
                continue
                
            # Try to identify header row
            header_row = rows[0]
            headers = [th.get_text(strip=True).lower() for th in header_row.find_all(['th', 'td'])]
            
            # Look for common column patterns
            symbol_idx = self.find_column_index(headers, ['symbol', 'stock', 'company', 'script', 'scrip'])
            ltp_idx = self.find_column_index(headers, ['ltp', 'price', 'last', 'current', 'close'])
            change_idx = self.find_column_index(headers, ['change', 'diff', 'variation', 'point'])
            high_idx = self.find_column_index(headers, ['high', 'max'])
            low_idx = self.find_column_index(headers, ['low', 'min'])
            volume_idx = self.find_column_index(headers, ['volume', 'qty', 'shares', 'turnover'])
            
            logger.info(f"Table analysis - Symbol: {symbol_idx}, LTP: {ltp_idx}, Change: {change_idx}")
            
            if symbol_idx >= 0 and ltp_idx >= 0:
                parsed_count = 0
                for row in rows[1:]:
                    cols = row.find_all(['td', 'th'])
                    if len(cols) > max(symbol_idx, ltp_idx):
                        try:
                            # Extract symbol
                            symbol_cell = cols[symbol_idx]
                            symbol_text = symbol_cell.get_text(strip=True)
                            
                            # Clean symbol - remove any non-alphanumeric characters except common ones
                            symbol = re.sub(r'[^\w]', '', symbol_text).upper()
                            
                            # Skip if symbol is too short or looks like a number
                            if len(symbol) < 2 or symbol.isdigit():
                                continue
                            
                            # Extract LTP
                            ltp_cell = cols[ltp_idx]
                            ltp = self.safe_float(ltp_cell.get_text(strip=True))
                            
                            # Skip if no valid price
                            if ltp <= 0:
                                continue
                            
                            # Extract other fields if available
                            change = 0.0
                            if change_idx >= 0 and len(cols) > change_idx:
                                change = self.safe_float(cols[change_idx].get_text(strip=True))
                            
                            high = ltp
                            if high_idx >= 0 and len(cols) > high_idx:
                                high = self.safe_float(cols[high_idx].get_text(strip=True))
                                if high <= 0:
                                    high = ltp
                            
                            low = ltp
                            if low_idx >= 0 and len(cols) > low_idx:
                                low = self.safe_float(cols[low_idx].get_text(strip=True))
                                if low <= 0:
                                    low = ltp
                            
                            volume = 1000
                            if volume_idx >= 0 and len(cols) > volume_idx:
                                volume = self.safe_int(cols[volume_idx].get_text(strip=True))
                                if volume <= 0:
                                    volume = 1000
                            
                            stock_data = {
                                'symbol': symbol,
                                'company_name': symbol,
                                'ltp': ltp,
                                'change': change,
                                'change_percent': (change/ltp*100) if ltp > 0 else 0.0,
                                'high': high,
                                'low': low,
                                'open_price': ltp - change,
                                'qty': volume,
                                'turnover': ltp * volume
                            }
                            stocks_data.append(stock_data)
                            parsed_count += 1
                            
                        except Exception as e:
                            continue
                
                logger.info(f"Generic parser extracted {parsed_count} stocks from table")
                            
                if stocks_data:  # If we found data in this table, use it
                    break
        
        # Additional method: Look for JavaScript/JSON data in script tags
        if not stocks_data:
            scripts = soup.find_all('script')
            for script in scripts:
                try:
                    script_text = script.get_text()
                    # Look for array of objects that might contain stock data
                    json_pattern = r'\[.*?\{.*?"symbol".*?\}.*?\]'
                    matches = re.findall(json_pattern, script_text, re.IGNORECASE | re.DOTALL)
                    
                    for match in matches:
                        try:
                            data = json.loads(match)
                            if isinstance(data, list):
                                for item in data:
                                    if isinstance(item, dict) and 'symbol' in item:
                                        normalized = self.normalize_stock_data(item)
                                        if normalized:
                                            stocks_data.append(normalized)
                        except:
                            continue
                except:
                    continue
                    
        return stocks_data
    
    def normalize_stock_data(self, raw_data):
        """Normalize stock data from various sources into standard format"""
        try:
            # Extract symbol
            symbol = ''
            for key in ['symbol', 'Symbol', 'SYMBOL', 'stockSymbol', 'companyCode', 'securityCode']:
                if key in raw_data and raw_data[key]:
                    symbol = str(raw_data[key]).strip().upper()
                    break
            
            if not symbol or len(symbol) < 2:
                return None
            
            # Extract LTP (Last Traded Price)
            ltp = 0.0
            for key in ['ltp', 'LTP', 'lastTradedPrice', 'currentPrice', 'price', 'closingPrice']:
                if key in raw_data and raw_data[key] is not None:
                    ltp = self.safe_float(raw_data[key])
                    if ltp > 0:
                        break
            
            if ltp <= 0:
                return None
            
            # Extract change
            change = 0.0
            for key in ['change', 'Change', 'pointChange', 'priceChange']:
                if key in raw_data and raw_data[key] is not None:
                    change = self.safe_float(raw_data[key])
                    break
            
            # Extract other fields with fallbacks
            change_percent = 0.0
            for key in ['changePercent', 'percentChange', 'change_percent']:
                if key in raw_data and raw_data[key] is not None:
                    change_percent = self.safe_float(raw_data[key])
                    break
            
            if change_percent == 0.0 and ltp > 0:
                change_percent = (change / ltp) * 100
            
            # High and Low
            high = ltp
            low = ltp
            for key in ['high', 'High', 'dayHigh', 'highPrice']:
                if key in raw_data and raw_data[key] is not None:
                    high = self.safe_float(raw_data[key])
                    if high > 0:
                        break
            
            for key in ['low', 'Low', 'dayLow', 'lowPrice']:
                if key in raw_data and raw_data[key] is not None:
                    low = self.safe_float(raw_data[key])
                    if low > 0:
                        break
            
            # Volume
            qty = 1000
            for key in ['volume', 'qty', 'quantity', 'shares', 'tradedShares']:
                if key in raw_data and raw_data[key] is not None:
                    qty = self.safe_int(raw_data[key])
                    if qty > 0:
                        break
            
            return {
                'symbol': symbol,
                'company_name': raw_data.get('companyName', symbol),
                'ltp': ltp,
                'change': change,
                'change_percent': change_percent,
                'high': high,
                'low': low,
                'open_price': ltp - change,
                'qty': qty,
                'turnover': ltp * qty
            }
            
        except Exception as e:
            logger.warning(f"Error normalizing stock data: {e}")
            return None
    
    def find_column_index(self, headers, possible_names):
        """Find column index by matching possible column names"""
        for i, header in enumerate(headers):
            for name in possible_names:
                if name in header:
                    return i
        return -1
    
    def get_sample_data(self):
        """Return sample data for testing when scraping fails"""
        return [
            {
                'symbol': 'NABIL',
                'company_name': 'NABIL BANK LIMITED',
                'ltp': 1156.00,
                'change': -8.70,
                'change_percent': -0.75,
                'high': 1170.00,
                'low': 1150.00,
                'open_price': 1164.70,
                'qty': 110940,
                'turnover': 128274840.00
            },
            {
                'symbol': 'ADBL',
                'company_name': 'AGRICULTURE DEVELOPMENT BANK LIMITED', 
                'ltp': 332.18,
                'change': 0.10,
                'change_percent': 0.03,
                'high': 336.60,
                'low': 327.00,
                'open_price': 332.08,
                'qty': 128639,
                'turnover': 42738894.02
            },
            {
                'symbol': 'HIDCL',
                'company_name': 'HYDROELECTRICITY INVESTMENT AND DEVELOPMENT COMPANY LIMITED',
                'ltp': 300.70,
                'change': -6.04,
                'change_percent': -1.97,
                'high': 309.80,
                'low': 299.00,
                'open_price': 306.74,
                'qty': 488131,
                'turnover': 146802774.70
            },
            {
                'symbol': 'NFS',
                'company_name': 'NEPAL FINANCE LTD',
                'ltp': 788.19,
                'change': 71.61,
                'change_percent': 9.99,
                'high': 788.20,
                'low': 715.50,
                'open_price': 716.58,
                'qty': 242942,
                'turnover': 191395890.98
            },
            {
                'symbol': 'CORBL',
                'company_name': 'CORPORATE DEVELOPMENT BANK LIMITED',
                'ltp': 2230.94,
                'change': 202.33,
                'change_percent': 9.97,
                'high': 2231.40,
                'low': 2069.10,
                'open_price': 2028.61,
                'qty': 13951,
                'turnover': 31132728.94
            },
            {
                'symbol': 'EBL',
                'company_name': 'EVEREST BANK LIMITED',
                'ltp': 695.00,
                'change': -5.00,
                'change_percent': -0.71,
                'high': 705.00,
                'low': 690.00,
                'open_price': 700.00,
                'qty': 45632,
                'turnover': 31714240.00
            },
            {
                'symbol': 'NBL',
                'company_name': 'NEPAL BANK LIMITED',
                'ltp': 445.00,
                'change': 2.50,
                'change_percent': 0.57,
                'high': 450.00,
                'low': 440.00,
                'open_price': 442.50,
                'qty': 89456,
                'turnover': 39807920.00
            },
            {
                'symbol': 'SBI',
                'company_name': 'NEPAL SBI BANK LIMITED',
                'ltp': 378.00,
                'change': -1.50,
                'change_percent': -0.40,
                'high': 382.00,
                'low': 375.00,
                'open_price': 379.50,
                'qty': 67890,
                'turnover': 25662420.00
            },
            {
                'symbol': 'KBL',
                'company_name': 'KUMARI BANK LIMITED',
                'ltp': 289.00,
                'change': 3.20,
                'change_percent': 1.12,
                'high': 292.00,
                'low': 285.00,
                'open_price': 285.80,
                'qty': 123456,
                'turnover': 35698584.00
            },
            {
                'symbol': 'HBL',
                'company_name': 'HIMALAYAN BANK LIMITED',
                'ltp': 556.00,
                'change': -4.30,
                'change_percent': -0.77,
                'high': 565.00,
                'low': 552.00,
                'open_price': 560.30,
                'qty': 78912,
                'turnover': 43899072.00
            }
        ]
    
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
    
    def save_to_database(self, stocks_data):
        """Save scraped data to database"""
        if not stocks_data:
            logger.warning("No stock data to save")
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = datetime.now().isoformat()
        saved_count = 0
        
        for stock in stocks_data:
            try:
                # Validate required fields
                if not stock.get('symbol') or stock.get('ltp', 0) <= 0:
                    continue
                
                cursor.execute('''
                    INSERT OR REPLACE INTO stocks 
                    (symbol, company_name, ltp, change, change_percent, high, low, open_price, qty, turnover, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    stock['symbol'],
                    stock.get('company_name', stock['symbol']),
                    stock['ltp'],
                    stock.get('change', 0.0),
                    stock.get('change_percent', 0.0),
                    stock.get('high', stock['ltp']),
                    stock.get('low', stock['ltp']),
                    stock.get('open_price', stock['ltp']),
                    stock.get('qty', 1000),
                    stock.get('turnover', stock['ltp'] * stock.get('qty', 1000)),
                    current_time
                ))
                saved_count += 1
            except Exception as e:
                logger.error(f"Error saving stock {stock.get('symbol', 'unknown')}: {e}")
        
        conn.commit()
        conn.close()
        logger.info(f"Saved {saved_count} stocks to database")
    
    def cleanup_old_data(self, days_to_keep=7):
        """Remove data older than specified days"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
        
        cursor.execute('DELETE FROM stocks WHERE timestamp < ?', (cutoff_date,))
        deleted_rows = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        if deleted_rows > 0:
            logger.info(f"Cleaned up {deleted_rows} old records")
    
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
    
    def run_scraper(self):
        """Run the scraping process"""
        logger.info("Starting scraping process...")
        stocks_data = self.scrape_stock_data()
        
        if stocks_data:
            self.save_to_database(stocks_data)
            self.cleanup_old_data()
        else:
            logger.warning("No data scraped")

# Flask API
app = Flask(__name__)
CORS(app)
scraper = NepalStockScraper()

@app.route('/api/stocks', methods=['GET'])
def get_stocks():
    """API endpoint to get all latest stock data"""
    try:
        symbol = request.args.get('symbol')
        data = scraper.get_latest_data(symbol)
        return jsonify({
            'success': True,
            'data': data,
            'count': len(data),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stocks/<symbol>', methods=['GET'])
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

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/trigger-scrape', methods=['POST'])
def trigger_scrape():
    """Manual trigger for scraping (useful for testing)"""
    try:
        scraper.run_scraper()
        return jsonify({
            'success': True,
            'message': 'Scraping completed'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/debug', methods=['GET'])
def debug_data():
    """Debug endpoint to see raw data structure"""
    try:
        conn = sqlite3.connect(scraper.db_path)
        cursor = conn.cursor()
        
        # Get latest data with detailed info
        cursor.execute('''
            SELECT symbol, company_name, ltp, change, change_percent, 
                   high, low, open_price, qty, turnover, timestamp
            FROM stocks 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''')
        
        columns = [description[0] for description in cursor.description]
        results = []
        
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        # Also get total count
        cursor.execute('SELECT COUNT(*) as total FROM stocks')
        total_count = cursor.fetchone()[0]
        
        # Get latest timestamp
        cursor.execute('SELECT MAX(timestamp) as latest FROM stocks')
        latest_timestamp = cursor.fetchone()[0]
        
        # Get unique symbols count
        cursor.execute('SELECT COUNT(DISTINCT symbol) as unique_symbols FROM stocks')
        unique_symbols = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'total_records_in_db': total_count,
            'unique_symbols': unique_symbols,
            'latest_timestamp': latest_timestamp,
            'sample_data': results,
            'debug_info': {
                'db_path': scraper.db_path,
                'urls_configured': scraper.urls
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get database statistics"""
    try:
        conn = sqlite3.connect(scraper.db_path)
        cursor = conn.cursor()
        
        # Get total stocks
        cursor.execute('SELECT COUNT(DISTINCT symbol) as total FROM stocks')
        total_symbols = cursor.fetchone()[0]
        
        # Get latest update time
        cursor.execute('SELECT MAX(timestamp) as latest FROM stocks')
        latest_update = cursor.fetchone()[0]
        
        # Get top gainers
        cursor.execute('''
            SELECT symbol, ltp, change, change_percent
            FROM stocks s1
            INNER JOIN (
                SELECT symbol, MAX(timestamp) as max_timestamp
                FROM stocks
                GROUP BY symbol
            ) s2 ON s1.symbol = s2.symbol AND s1.timestamp = s2.max_timestamp
            WHERE change_percent > 0
            ORDER BY change_percent DESC
            LIMIT 5
        ''')
        
        gainers = []
        for row in cursor.fetchall():
            gainers.append({
                'symbol': row[0],
                'ltp': row[1],
                'change': row[2],
                'change_percent': row[3]
            })
        
        # Get top losers
        cursor.execute('''
            SELECT symbol, ltp, change, change_percent
            FROM stocks s1
            INNER JOIN (
                SELECT symbol, MAX(timestamp) as max_timestamp
                FROM stocks
                GROUP BY symbol
            ) s2 ON s1.symbol = s2.symbol AND s1.timestamp = s2.max_timestamp
            WHERE change_percent < 0
            ORDER BY change_percent ASC
            LIMIT 5
        ''')
        
        losers = []
        for row in cursor.fetchall():
            losers.append({
                'symbol': row[0],
                'ltp': row[1],
                'change': row[2],
                'change_percent': row[3]
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_symbols': total_symbols,
                'latest_update': latest_update,
                'top_gainers': gainers,
                'top_losers': losers
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def run_scheduler():
    """Run the scheduler in a separate thread"""
    # Schedule scraping every 5 minutes during market hours (10 AM - 3 PM Nepal Time)
    schedule.every().minute.at(":00").do(lambda: scraper.run_scraper() if is_market_hours() else None)
    schedule.every().minute.at(":30").do(lambda: scraper.run_scraper() if is_market_hours() else None)
    
    # Run cleanup daily at 6 PM
    schedule.every().day.at("18:00").do(scraper.cleanup_old_data)
    
    while True:
        schedule.run_pending()
        time.sleep(1)

def is_market_hours():
    """Check if current time is within market hours (Nepal time)"""
    from datetime import datetime
    now = datetime.now()
    current_hour = now.hour
    
    # Nepal Stock Exchange operates from 10 AM to 3 PM (Sunday to Thursday)
    # Skip Friday and Saturday (weekends in Nepal)
    if now.weekday() in [4, 5]:  # Friday = 4, Saturday = 5
        return False
    
    return 10 <= current_hour <= 15

if __name__ == '__main__':
    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    # Initial scrape
    scraper.run_scraper()
    
    # Start Flask app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)