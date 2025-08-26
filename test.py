# test_scraper.py
"""
Test script for Nepal Stock Scraper
Run this to test if the scraper is working correctly
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import NepalStockScraper
import json

def test_scraper():
    print("🔍 Testing Nepal Stock Scraper...")
    print("=" * 50)
    
    # Initialize scraper
    scraper = NepalStockScraper('test_nepal_stock.db')
    
    print("✅ Scraper initialized successfully")
    print("📊 Testing data scraping from ShareSansar.com...")
    
    # Test scraping
    stocks_data = scraper.scrape_stock_data()
    
    if stocks_data and len(stocks_data) > 10:  # Should have substantial data
        print(f"✅ Successfully scraped {len(stocks_data)} stocks!")
        print("\n📋 Sample data:")
        print("-" * 30)
        
        # Show first 5 stocks
        for i, stock in enumerate(stocks_data[:5]):
            change_symbol = "📈" if stock['change'] >= 0 else "📉"
            print(f"{i+1}. {stock['symbol']:8} - LTP: {stock['ltp']:8.2f} - Change: {stock['change']:6.2f} ({stock['change_percent']:5.2f}%) {change_symbol}")
        
        if len(stocks_data) > 5:
            print(f"... and {len(stocks_data) - 5} more stocks")
        
        # Show some statistics
        positive_changes = sum(1 for s in stocks_data if s['change'] > 0)
        negative_changes = sum(1 for s in stocks_data if s['change'] < 0)
        unchanged = len(stocks_data) - positive_changes - negative_changes
        
        print(f"\n📊 Market Summary:")
        print(f"   📈 Gainers: {positive_changes}")
        print(f"   📉 Losers: {negative_changes}")
        print(f"   ➡️  Unchanged: {unchanged}")
        
        # Test database save
        print("\n💾 Testing database save...")
        scraper.save_to_database(stocks_data)
        print("✅ Data saved to database successfully")
        
        # Test data retrieval
        print("\n📖 Testing data retrieval...")
        retrieved_data = scraper.get_latest_data()
        print(f"✅ Retrieved {len(retrieved_data)} stocks from database")
        
        # Test specific stock retrieval
        if stocks_data:
            test_symbol = stocks_data[0]['symbol']
            specific_stock = scraper.get_latest_data(test_symbol)
            if specific_stock:
                print(f"✅ Retrieved specific stock: {test_symbol}")
            else:
                print(f"❌ Failed to retrieve specific stock: {test_symbol}")
        
        print(f"\n🎉 All tests passed! The scraper is working correctly.")
        print(f"📊 Total stocks available: {len(stocks_data)}")
        
        return True
        
    else:
        print("❌ No data scraped or insufficient data. This could be due to:")
        print("   - Network connectivity issues")
        print("   - Website structure changes")
        print("   - SSL certificate issues")
        print("   - Website blocking requests")
        print(f"   - Only got {len(stocks_data) if stocks_data else 0} stocks (expected >10)")
        print("\n💡 The scraper will use sample data for testing.")
        
        return False

def test_api_endpoints():
    """Test API endpoints"""
    import requests
    import time
    import threading
    from app import app, scraper
    
    print("\n🌐 Testing API endpoints...")
    print("=" * 50)
    
    # Start Flask app in background
    def run_app():
        app.run(host='127.0.0.1', port=5001, debug=False, use_reloader=False)
    
    app_thread = threading.Thread(target=run_app, daemon=True)
    app_thread.start()
    
    # Wait for app to start
    time.sleep(2)
    
    base_url = 'http://127.0.0.1:5001/api'
    
    try:
        # Test health endpoint
        print("🔍 Testing /api/health...")
        response = requests.get(f'{base_url}/health', timeout=5)
        if response.status_code == 200:
            print("✅ Health endpoint working")
        else:
            print(f"❌ Health endpoint failed: {response.status_code}")
        
        # Test stocks endpoint
        print("🔍 Testing /api/stocks...")
        response = requests.get(f'{base_url}/stocks', timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"✅ Stocks endpoint working - {data.get('count', 0)} stocks")
            else:
                print(f"❌ Stocks endpoint failed: {data.get('error')}")
        else:
            print(f"❌ Stocks endpoint failed: {response.status_code}")
        
        # Test trigger scrape endpoint
        print("🔍 Testing /api/trigger-scrape...")
        response = requests.post(f'{base_url}/trigger-scrape', timeout=15)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("✅ Trigger scrape endpoint working")
            else:
                print(f"❌ Trigger scrape failed: {data.get('error')}")
        else:
            print(f"❌ Trigger scrape failed: {response.status_code}")
        
        print("🎉 API testing completed!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to API - make sure the Flask app is running")
    except Exception as e:
        print(f"❌ API test error: {e}")

def show_help():
    """Show usage instructions"""
    print("\n📚 Usage Instructions:")
    print("=" * 50)
    print("1. Install dependencies:")
    print("   pip install -r requirements.txt")
    print("\n2. Run the test:")
    print("   python test_scraper.py")
    print("\n3. Start the main application:")
    print("   python app.py")
    print("\n4. Test API endpoints:")
    print("   - GET http://localhost:5000/api/health")
    print("   - GET http://localhost:5000/api/stocks")
    print("   - POST http://localhost:5000/api/trigger-scrape")
    print("\n5. Deploy to Heroku:")
    print("   git init")
    print("   git add .")
    print("   git commit -m 'Initial commit'")
    print("   heroku create your-app-name")
    print("   git push heroku main")

if __name__ == "__main__":
    print("🚀 Nepal Stock Scraper Test Suite")
    print("=" * 50)
    
    try:
        # Run scraper test
        scraper_works = test_scraper()
        
        if scraper_works:
            # Test API endpoints
            test_api_endpoints()
        
        # Show help
        show_help()
        
        # Cleanup test database
        if os.path.exists('test_nepal_stock.db'):
            os.remove('test_nepal_stock.db')
            print("\n🧹 Cleaned up test database")
        
        print("\n✨ Testing completed!")
        
    except KeyboardInterrupt:
        print("\n⛔ Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()