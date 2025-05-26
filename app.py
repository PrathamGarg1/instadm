import os
import time
import random
import pandas as pd
import sqlite3
import hashlib
import secrets
import hmac
import json
import threading
import uuid
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests
from functools import wraps
from dotenv import load_dotenv


import os
import time
import random
import pandas as pd
import sqlite3
import hashlib
import secrets
import hmac
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options


from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import threading
import uuid
import requests
from functools import wraps
import json
from dotenv import load_dotenv




load_dotenv(override=True)

print("balle balle")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
print("LEMON_SQUEEZY_API_KEY:", os.environ.get('LEMON_SQUEEZY_API_KEY'))

print("balle balle")

app = Flask(__name__)

# In your app.py file, update this section:

# Google OAuth Configuration with error checking
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

NGROK_URL = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5000')  # Replace with your actual ngrok URL



# Add error checking here in app.py, not config.py
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    print("❌ WARNING: Google OAuth credentials not found in environment variables!")

client_config = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [f"{NGROK_URL}/callback"]
    }
}


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Lemon Squeezy Configuration
app.config['LEMON_SQUEEZY_API_KEY'] = os.environ.get('LEMON_SQUEEZY_API_KEY')
app.config['LEMON_SQUEEZY_STORE_ID'] = os.environ.get('LEMON_SQUEEZY_STORE_ID')
app.config['LEMON_SQUEEZY_VARIANT_ID'] =  os.environ.get('LEMON_SQUEEZY_VARIANT_ID')
app.config['LEMON_SQUEEZY_WEBHOOK_SECRET'] = os.environ.get('LEMON_SQUEEZY_WEBHOOK_SECRET')

# Set to False for production with real payments
TESTING_MODE = False

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)



# Force database creation - add this right after imports
def create_database():
    """Force create database with all required tables"""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    try:
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                google_id TEXT UNIQUE,
                name TEXT,
                picture TEXT,
                subscription_status TEXT DEFAULT 'inactive',
                subscription_id TEXT,
                lemon_squeezy_customer_id TEXT,
                subscription_expires TIMESTAMP,
                trial_expires TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create campaigns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                status TEXT DEFAULT 'pending',
                progress REAL DEFAULT 0,
                successful_sends INTEGER DEFAULT 0,
                failed_sends INTEGER DEFAULT 0,
                total_recipients INTEGER DEFAULT 0,
                message_template TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create subscription_events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subscription_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                lemon_squeezy_subscription_id TEXT,
                event_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        print("✅ Database created successfully!")
        
    except Exception as e:
        print(f"❌ Database creation error: {e}")
        conn.rollback()
    finally:
        conn.close()

# Call this immediately
create_database()


# Add this after your imports but before the routes
def fix_database_schema():
    """Ensure the database has all required tables and columns"""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    try:
        # Drop and recreate users table with all required columns
        cursor.execute('DROP TABLE IF EXISTS users')
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                google_id TEXT UNIQUE,
                name TEXT,
                picture TEXT,
                subscription_status TEXT DEFAULT 'inactive',
                subscription_id TEXT,
                lemon_squeezy_customer_id TEXT,
                subscription_expires TIMESTAMP,
                trial_expires TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Recreate campaigns table
        cursor.execute('DROP TABLE IF EXISTS campaigns')
        cursor.execute('''
            CREATE TABLE campaigns (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                status TEXT DEFAULT 'pending',
                progress REAL DEFAULT 0,
                successful_sends INTEGER DEFAULT 0,
                failed_sends INTEGER DEFAULT 0,
                total_recipients INTEGER DEFAULT 0,
                message_template TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Recreate subscription_events table
        cursor.execute('DROP TABLE IF EXISTS subscription_events')
        cursor.execute('''
            CREATE TABLE subscription_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                lemon_squeezy_subscription_id TEXT,
                event_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        print("✅ Database schema fixed successfully!")
        
    except Exception as e:
        print(f"❌ Error fixing database: {e}")
        conn.rollback()
    finally:
        conn.close()



# Enhanced Database setup
def init_db():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # Users table with subscription tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            subscription_status TEXT DEFAULT 'inactive',
            subscription_id TEXT,
            lemon_squeezy_customer_id TEXT,
            subscription_expires TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            trial_expires TIMESTAMP
        )
    ''')
    
    # Campaigns table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            status TEXT DEFAULT 'pending',
            progress REAL DEFAULT 0,
            successful_sends INTEGER DEFAULT 0,
            failed_sends INTEGER DEFAULT 0,
            total_recipients INTEGER DEFAULT 0,
            message_template TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Subscription events table for tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscription_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            lemon_squeezy_subscription_id TEXT,
            event_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()
fix_database_schema()  # Add this line

# Store campaign status
campaigns = {}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()





def verify_webhook_signature(payload, signature, secret):
    """Verify Lemon Squeezy webhook signature with debug logging"""
    if not signature or not secret:
        print(f"❌ Missing signature or secret: sig={bool(signature)}, secret={bool(secret)}")
        return False
    
    computed_hash = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    )
    expected_signature = computed_hash.hexdigest()
    
    print(f"🔍 Signature verification:")
    print(f"   Expected: {expected_signature}")
    print(f"   Received: {signature}")
    print(f"   Match: {hmac.compare_digest(expected_signature, signature)}")
    
    return hmac.compare_digest(expected_signature, signature)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT subscription_status, subscription_id, trial_expires, subscription_expires, email 
            FROM users WHERE id = ?
        ''', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return redirect(url_for('login'))
        
        subscription_status, subscription_id, trial_expires, subscription_expires, email = user
        print(f"🔍 User {email} - Status: {subscription_status}, Sub ID: {subscription_id}")
        
        # Check if user has active subscription or trial
        if subscription_status in ['on_trial', 'active', 'cancelled']:
            # For trials, check if still valid
            if subscription_status == 'on_trial' and trial_expires:
                try:
                    trial_end = datetime.fromisoformat(trial_expires.replace('Z', '+00:00'))
                    if datetime.now() > trial_end:
                        print(f"❌ Trial expired for {email}")
                        flash('Your trial has expired. Please subscribe to continue.', 'warning')
                        return redirect(url_for('pricing'))
                except:
                    pass
            
            return f(*args, **kwargs)
        
        print(f"❌ User {email} needs subscription - Status: {subscription_status}")
        flash('🔒 Please subscribe to start your free trial and access InstaBulk Pro.', 'warning')
        return redirect(url_for('pricing'))
    
    return decorated_function


class InstagramBulkMessenger:
    def __init__(self, username, password, csv_data, message_template, campaign_id, user_id):
        self.username = username
        self.password = password
        self.csv_data = csv_data
        self.message_template = message_template
        self.campaign_id = campaign_id
        self.user_id = user_id
        self.status = "initializing"
        self.progress = 0
        self.results = {"successful": 0, "failed": 0, "total": len(csv_data)}
        
        # Setup Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--headless")  # Run in headless mode for production
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        self.driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=chrome_options
        )
        self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        self.wait = WebDriverWait(self.driver, 20)

    def human_type(self, element, text, delay_range=(0.1, 0.3)):
        for char in text:
            element.send_keys(char)
            time.sleep(random.uniform(*delay_range))

    def personalize_message(self, row):
        message = self.message_template
        for column, value in row.items():
            placeholder = "{" + str(column) + "}"
            message = message.replace(placeholder, str(value))
        return message

    def handle_popup_screens(self):
        popup_handlers = [
            ("//button[contains(text(), 'Not Now')]", "Notifications popup"),
            ("//button[text()='Not Now']", "Notifications popup (exact match)"),
            ("//button[contains(text(), 'Not now')]", "Save login info popup"),
            ("//button[text()='Not now']", "Save login info popup (exact match)"),
            ("//button[contains(text(), 'Cancel')]", "Add to home screen popup"),
        ]
        
        for xpath, description in popup_handlers:
            try:
                popup_button = WebDriverWait(self.driver, 3).until(
                    EC.element_to_be_clickable((By.XPATH, xpath))
                )
                popup_button.click()
                time.sleep(random.uniform(2, 4))
            except (NoSuchElementException, TimeoutException):
                continue

    def login(self):
        try:
            self.status = "logging_in"
            self.update_campaign_status()
            
            self.driver.get('https://www.instagram.com/accounts/login/')
            time.sleep(random.uniform(5, 8))
            
            username_input = self.wait.until(
                EC.presence_of_element_located((By.NAME, 'username'))
            )
            time.sleep(random.uniform(1, 2))
            self.human_type(username_input, self.username)
            
            time.sleep(random.uniform(1, 3))
            
            password_input = self.driver.find_element(By.NAME, 'password')
            self.human_type(password_input, self.password)
            
            time.sleep(random.uniform(2, 4))
            password_input.send_keys(Keys.RETURN)
            
            time.sleep(random.uniform(8, 12))
            self.handle_popup_screens()
            time.sleep(random.uniform(3, 6))
            
            try:
                self.wait.until(
                    EC.any_of(
                        EC.presence_of_element_located((By.XPATH, "//a[@href='/']")),
                        EC.presence_of_element_located((By.XPATH, "//svg[@aria-label='Home']")),
                        EC.presence_of_element_located((By.XPATH, "//span[text()='Home']"))
                    )
                )
                return True
            except TimeoutException:
                return False
                
        except Exception as e:
            return False

    def send_message(self, instagram_handle, personalized_message):
        try:
            profile_url = f'https://www.instagram.com/{instagram_handle}/'
            self.driver.get(profile_url)
            time.sleep(random.uniform(5, 8))
            
            message_button_selectors = [
                "//div[text()='Message']",
                "//button[text()='Message']",
                "//div[@role='button'][contains(text(), 'Message')]",
                "//button[contains(text(), 'Message')]"
            ]
            
            message_button_found = False
            for selector in message_button_selectors:
                try:
                    message_button = self.wait.until(
                        EC.element_to_be_clickable((By.XPATH, selector))
                    )
                    self.driver.execute_script("arguments[0].scrollIntoView(true);", message_button)
                    time.sleep(random.uniform(1, 2))
                    message_button.click()
                    time.sleep(random.uniform(4, 7))
                    message_button_found = True
                    break
                except (NoSuchElementException, TimeoutException):
                    continue
            
            if not message_button_found:
                return False
            
            try:
                not_now_button = WebDriverWait(self.driver, 5).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[text()='Not Now']"))
                )
                not_now_button.click()
                time.sleep(random.uniform(2, 4))
            except TimeoutException:
                pass
            
            message_input_selectors = [
                "//textarea[@placeholder='Message...']",
                "//div[@contenteditable='true'][@data-lexical-editor='true']",
                "//div[@contenteditable='true'][contains(@aria-label, 'Message')]",
                "//div[@role='textbox']"
            ]
            
            for selector in message_input_selectors:
                try:
                    message_input = self.wait.until(
                        EC.element_to_be_clickable((By.XPATH, selector))
                    )
                    message_input.click()
                    time.sleep(random.uniform(1, 2))
                    message_input.clear()
                    time.sleep(random.uniform(0.5, 1))
                    
                    self.human_type(message_input, personalized_message, delay_range=(0.05, 0.15))
                    time.sleep(random.uniform(2, 4))
                    
                    message_input.send_keys(Keys.RETURN)
                    time.sleep(random.uniform(3, 6))
                    return True
                    
                except (NoSuchElementException, TimeoutException):
                    continue
            
            return False
            
        except Exception as e:
            return False

    def update_campaign_status(self):
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE campaigns 
            SET status = ?, progress = ?, successful_sends = ?, failed_sends = ?
            WHERE id = ?
        ''', (self.status, self.progress, self.results["successful"], self.results["failed"], self.campaign_id))
        conn.commit()
        conn.close()
        
        campaigns[self.campaign_id] = {
            "status": self.status,
            "progress": self.progress,
            "results": self.results
        }

    def run_campaign(self):
        try:
            if not self.login():
                self.status = "login_failed"
                self.update_campaign_status()
                return
            
            self.status = "sending_messages"
            self.update_campaign_status()
            
            for index, row in self.csv_data.iterrows():
                instagram_handle = row.get('instagram_handle', '')
                if not instagram_handle:
                    self.results["failed"] += 1
                    continue
                
                personalized_message = self.personalize_message(row)
                
                if self.send_message(instagram_handle, personalized_message):
                    self.results["successful"] += 1
                else:
                    self.results["failed"] += 1
                
                self.progress = ((index + 1) / len(self.csv_data)) * 100
                self.update_campaign_status()
                
                if index < len(self.csv_data) - 1:
                    delay = random.randint(60, 150)
                    time.sleep(delay)
            
            self.status = "completed"
            self.update_campaign_status()
            
            # Update database with completion
            conn = sqlite3.connect('app.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE campaigns SET completed_at = ? WHERE id = ?', 
                         (datetime.now().isoformat(), self.campaign_id))
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.status = "error"
            self.update_campaign_status()
        finally:
            self.driver.quit()


# Routes
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            flash('Email already registered', 'error')
            conn.close()
            return render_template('register.html')
        
        # Create user WITHOUT local trial - they must subscribe to get access
        password_hash = hash_password(password)
        
        cursor.execute('''
            INSERT INTO users (email, password_hash, subscription_status) 
            VALUES (?, ?, 'inactive')
        ''', (email, password_hash))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        session['user_id'] = user_id
        session['email'] = email
        flash('Account created! Please subscribe to start your free trial.', 'success')
        return redirect(url_for('pricing'))  # Redirect to pricing, not dashboard
    
    return render_template('register.html')




@app.route('/login')
def login():
    try:
        # Get your current ngrok URL - CHANGE THIS to your actual ngrok URL
        NGROK_URL = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5000')
        
        flow = Flow.from_client_config(
            client_config,
            scopes=[
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ],  # ✅ Use full URLs instead of 'email', 'profile'
            redirect_uri=f"{NGROK_URL}/callback"
        )
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        session['state'] = state
        session.permanent = True
        
        print(f"✅ Using redirect URI: {NGROK_URL}/callback")  # Debug
        
        return redirect(authorization_url)
        
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        flash('Login initialization failed. Please try again.', 'error')
        return redirect(url_for('landing'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/create-checkout', methods=['POST'])
@login_required
def create_checkout():
    try:
        api_key = os.environ.get('LEMON_SQUEEZY_API_KEY')
        
        if not api_key:
            return jsonify({'error': 'API key not configured'}), 500
        
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/vnd.api+json',
            'Accept': 'application/vnd.api+json'
        }
        
        # Set redirect URL
        NGROK_URL = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5000')
        redirect_url = f"{NGROK_URL}/payment-success"
        
        data = {
            'data': {
                'type': 'checkouts',
                'attributes': {
                    'checkout_data': {
                        'email': session['email'],  # This ensures email is passed
                        'name': session.get('name', session['email']),
                        'custom': {
                            'user_id': str(session['user_id']),
                            'user_email': session['email']  # Additional email reference
                        }
                    },
                    'checkout_options': {
                        'embed': False,
                        'media': False,
                        'logo': True,
                        'desc': True,
                        'discount': True,
                        'dark': False,
                        'subscription_preview': True,
                        'button_color': '#6366f1'
                    },
                    'product_options': {
                        'enabled_variants': [int(os.environ.get('LEMON_SQUEEZY_VARIANT_ID'))],
                        'redirect_url': redirect_url,
                        'receipt_button_text': 'Access Dashboard',
                        'receipt_link_url': redirect_url,
                        'receipt_thank_you_note': 'Welcome to InstaBulk Pro! Your subscription is now active.'
                    }
                },
                'relationships': {
                    'store': {
                        'data': {
                            'type': 'stores',
                            'id': str(os.environ.get('LEMON_SQUEEZY_STORE_ID'))
                        }
                    },
                    'variant': {
                        'data': {
                            'type': 'variants',
                            'id': str(os.environ.get('LEMON_SQUEEZY_VARIANT_ID'))
                        }
                    }
                }
            }
        }
        
        print(f"🔍 Creating checkout for user {session['user_id']} with email {session['email']}")
        
        response = requests.post(
            'https://api.lemonsqueezy.com/v1/checkouts',
            headers=headers,
            json=data
        )
        
        if response.status_code == 201:
            checkout_data = response.json()
            checkout_url = checkout_data['data']['attributes']['url']
            return jsonify({'checkout_url': checkout_url})
        else:
            print(f"Lemon Squeezy Error: {response.status_code} - {response.text}")
            return jsonify({'error': 'Failed to create checkout'}), 500
            
    except Exception as e:
        print(f"Exception in checkout: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/webhook', methods=['POST'])
def webhook():
    """Handle Lemon Squeezy webhooks"""
    try:
        # Get the raw payload as bytes
        payload = request.get_data()
        
        # Get the signature from X-Signature header
        signature = request.headers.get('X-Signature')
        
        if not signature:
            print("Webhook Error: X-Signature header missing")
            return jsonify({'error': 'Missing signature'}), 400
        
        # Verify the webhook signature
        if not verify_webhook_signature(payload, signature, app.config['LEMON_SQUEEZY_WEBHOOK_SECRET']):
            print("Webhook Error: Invalid signature")
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Parse the JSON payload
        event_data = json.loads(payload.decode('utf-8'))
        event_name = event_data['meta']['event_name']
        
        print(f"✅ Verified webhook: {event_name}")
        
        # Process the webhook events
        if event_name == 'subscription_created':
            handle_subscription_created(event_data)
        elif event_name == 'subscription_updated':
            handle_subscription_updated(event_data)
        elif event_name == 'subscription_cancelled':
            handle_subscription_cancelled(event_data)
        elif event_name == 'subscription_resumed':
            handle_subscription_resumed(event_data)
        elif event_name == 'subscription_expired':
            handle_subscription_expired(event_data)
        elif event_name == 'subscription_paused':
            handle_subscription_paused(event_data)
        elif event_name == 'subscription_unpaused':
            handle_subscription_unpaused(event_data)
        
        return jsonify({'status': 'success'})
        
    except json.JSONDecodeError:
        print("Webhook Error: Invalid JSON payload")
        return jsonify({'error': 'Invalid JSON'}), 400
    except Exception as e:
        print(f"Webhook Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/debug-subscription-status')
def debug_subscription_status():
    """Debug route to check subscription status"""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, email, subscription_status, subscription_id, lemon_squeezy_customer_id
        FROM users WHERE id = ?
    ''', (session['user_id'],))
    user_data = cursor.fetchone()
    
    cursor.execute('SELECT * FROM subscription_events WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],))
    events = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'user_data': user_data,
        'subscription_events': events,
        'session_user_id': session.get('user_id'),
        'session_email': session.get('email')
    })



def handle_subscription_created(event_data):
    """Handle new subscription creation with improved email-based user matching"""
    try:
        subscription = event_data['data']
        attributes = subscription['attributes']
        
        # Extract all possible email sources from webhook
        customer_email = attributes.get('customer_email')
        user_email = attributes.get('user_email') 
        billing_email = attributes.get('billing_email')
        
        # Extract from custom_data
        custom_data = attributes.get('custom_data', {})
        custom_user_id = custom_data.get('user_id')
        custom_user_email = custom_data.get('user_email')
        
        # Extract from order attributes if present
        order_attrs = attributes.get('order', {})
        order_email = order_attrs.get('user_email') if isinstance(order_attrs, dict) else None
        
        print(f"🔍 Subscription created webhook received:")
        print(f"   - Subscription ID: {subscription['id']}")
        print(f"   - Customer Email: {customer_email}")
        print(f"   - User Email: {user_email}")
        print(f"   - Billing Email: {billing_email}")
        print(f"   - Custom User ID: {custom_user_id}")
        print(f"   - Custom User Email: {custom_user_email}")
        print(f"   - Order Email: {order_email}")
        
        # Find user by multiple email sources
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        target_user_id = None
        matched_email = None
        
        # Try all possible email sources
        email_sources = [
            customer_email,
            user_email,
            billing_email,
            custom_user_email,
            order_email
        ]
        
        # Remove None values and duplicates
        email_sources = list(set([email for email in email_sources if email]))
        
        print(f"🔍 Searching for user with emails: {email_sources}")
        
        # Method 1: Try direct user_id match first
        if custom_user_id:
            cursor.execute('SELECT id, email FROM users WHERE id = ?', (custom_user_id,))
            result = cursor.fetchone()
            if result:
                target_user_id = result[0]
                matched_email = result[1]
                print(f"✅ Found user by ID: {target_user_id} ({matched_email})")
        
        # Method 2: Try email matching
        if not target_user_id:
            for email in email_sources:
                if email:
                    cursor.execute('SELECT id, email FROM users WHERE email = ?', (email,))
                    result = cursor.fetchone()
                    if result:
                        target_user_id = result[0]
                        matched_email = result[1]
                        print(f"✅ Found user by email: {target_user_id} ({matched_email})")
                        break
        
        if not target_user_id:
            print(f"❌ No user found for subscription {subscription['id']}")
            # List all users for debugging
            cursor.execute('SELECT id, email FROM users')
            all_users = cursor.fetchall()
            print(f"🔍 Available users in database: {all_users}")
            conn.close()
            return
        
        # Update user subscription
        subscription_id = subscription['id']
        customer_id = attributes.get('customer_id')
        status = attributes.get('status', 'active')
        trial_ends_at = attributes.get('trial_ends_at')
        ends_at = attributes.get('ends_at')
        
        print(f"🔄 Updating user {target_user_id} with subscription data:")
        print(f"   - Status: {status}")
        print(f"   - Subscription ID: {subscription_id}")
        print(f"   - Customer ID: {customer_id}")
        
        cursor.execute('''
            UPDATE users 
            SET subscription_status = ?, 
                subscription_id = ?,
                lemon_squeezy_customer_id = ?,
                subscription_expires = ?,
                trial_expires = ?
            WHERE id = ?
        ''', (status, subscription_id, customer_id, ends_at, trial_ends_at, target_user_id))
        
        # Verify the update
        cursor.execute('SELECT subscription_status, subscription_id FROM users WHERE id = ?', (target_user_id,))
        updated_user = cursor.fetchone()
        print(f"✅ User updated - Status: {updated_user[0]}, Sub ID: {updated_user[1]}")
        
        # Log the event
        cursor.execute('''
            INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
            VALUES (?, ?, ?, ?)
        ''', (target_user_id, 'subscription_created', subscription_id, json.dumps(event_data)))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Subscription {subscription_id} successfully linked to user {target_user_id}")
        
    except Exception as e:
        print(f"❌ Error handling subscription_created: {str(e)}")
        import traceback
        traceback.print_exc()

def handle_subscription_updated(event_data):
    """Handle subscription updates with better user matching"""
    try:
        subscription = event_data['data']
        subscription_id = subscription['id']
        attributes = subscription['attributes']
        status = attributes.get('status')
        ends_at = attributes.get('ends_at')
        trial_ends_at = attributes.get('trial_ends_at')
        customer_email = attributes.get('customer_email')
        
        print(f"🔍 Updating subscription {subscription_id} to status: {status}")
        
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        # Try to find user by subscription_id first
        cursor.execute('SELECT id, email FROM users WHERE subscription_id = ?', (subscription_id,))
        user = cursor.fetchone()
        
        if user:
            user_id = user[0]
            print(f"✅ Found user {user_id} by subscription_id")
        else:
            # Try to find by email if subscription_id doesn't match
            if customer_email:
                cursor.execute('SELECT id, email FROM users WHERE email = ?', (customer_email,))
                user = cursor.fetchone()
                if user:
                    user_id = user[0]
                    print(f"✅ Found user {user_id} by email, updating subscription_id")
                    # Update the subscription_id for this user
                    cursor.execute('UPDATE users SET subscription_id = ? WHERE id = ?', (subscription_id, user_id))
                else:
                    print(f"❌ No user found for subscription {subscription_id}")
                    conn.close()
                    return
            else:
                print(f"❌ No user found for subscription {subscription_id}")
                conn.close()
                return
        
        # Update subscription status
        cursor.execute('''
            UPDATE users 
            SET subscription_status = ?,
                subscription_expires = ?,
                trial_expires = ?
            WHERE id = ?
        ''', (status, ends_at, trial_ends_at, user_id))
        
        # Verify the update
        cursor.execute('SELECT email, subscription_status FROM users WHERE id = ?', (user_id,))
        updated_user = cursor.fetchone()
        print(f"✅ User {updated_user[0]} updated to status: {updated_user[1]}")
        
        # Log the event
        cursor.execute('''
            INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
            VALUES (?, ?, ?, ?)
        ''', (user_id, 'subscription_updated', subscription_id, json.dumps(event_data)))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Subscription {subscription_id} updated to {status}")
        
    except Exception as e:
        print(f"❌ Error handling subscription_updated: {str(e)}")
        import traceback
        traceback.print_exc()


def handle_subscription_cancelled(event_data):
    """Handle subscription cancellation"""
    try:
        subscription = event_data['data']
        subscription_id = subscription['id']
        
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        # Update subscription status but keep access until expiry
        cursor.execute('''
            UPDATE users 
            SET subscription_status = 'cancelled'
            WHERE subscription_id = ?
        ''', (subscription_id,))
        
        # Log the event
        cursor.execute('''
            INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
            VALUES ((SELECT id FROM users WHERE subscription_id = ?), ?, ?, ?)
        ''', (subscription_id, 'subscription_cancelled', subscription_id, json.dumps(event_data)))
        
        conn.commit()
        conn.close()
        
        print(f"Subscription {subscription_id} cancelled")
        
    except Exception as e:
        print(f"Error handling subscription_cancelled: {str(e)}")

def handle_subscription_resumed(event_data):
    """Handle subscription resumption"""
    try:
        subscription = event_data['data']
        subscription_id = subscription['id']
        
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET subscription_status = 'active'
            WHERE subscription_id = ?
        ''', (subscription_id,))
        
        cursor.execute('''
            INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
            VALUES ((SELECT id FROM users WHERE subscription_id = ?), ?, ?, ?)
        ''', (subscription_id, 'subscription_resumed', subscription_id, json.dumps(event_data)))
        
        conn.commit()
        conn.close()
        
        print(f"Subscription {subscription_id} resumed")
        
    except Exception as e:
        print(f"Error handling subscription_resumed: {str(e)}")

def handle_subscription_expired(event_data):
    """Handle subscription expiration"""
    try:
        subscription = event_data['data']
        subscription_id = subscription['id']
        
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET subscription_status = 'expired'
            WHERE subscription_id = ?
        ''', (subscription_id,))
        
        cursor.execute('''
            INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
            VALUES ((SELECT id FROM users WHERE subscription_id = ?), ?, ?, ?)
        ''', (subscription_id, 'subscription_expired', subscription_id, json.dumps(event_data)))
        
        conn.commit()
        conn.close()
        
        print(f"Subscription {subscription_id} expired")
        
    except Exception as e:
        print(f"Error handling subscription_expired: {str(e)}")

def handle_subscription_paused(event_data):
    """Handle subscription pause"""
    try:
        subscription = event_data['data']
        subscription_id = subscription['id']
        
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET subscription_status = 'paused'
            WHERE subscription_id = ?
        ''', (subscription_id,))
        
        cursor.execute('''
            INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
            VALUES ((SELECT id FROM users WHERE subscription_id = ?), ?, ?, ?)
        ''', (subscription_id, 'subscription_paused', subscription_id, json.dumps(event_data)))
        
        conn.commit()
        conn.close()
        
        print(f"Subscription {subscription_id} paused")
        
    except Exception as e:
        print(f"Error handling subscription_paused: {str(e)}")

def handle_subscription_unpaused(event_data):
    """Handle subscription unpause"""
    try:
        subscription = event_data['data']
        subscription_id = subscription['id']
        
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET subscription_status = 'active'
            WHERE subscription_id = ?
        ''', (subscription_id,))
        
        cursor.execute('''
            INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
            VALUES ((SELECT id FROM users WHERE subscription_id = ?), ?, ?, ?)
        ''', (subscription_id, 'subscription_unpaused', subscription_id, json.dumps(event_data)))
        
        conn.commit()
        conn.close()
        
        print(f"Subscription {subscription_id} unpaused")
        
    except Exception as e:
        print(f"Error handling subscription_unpaused: {str(e)}")

@app.route('/dashboard')
@subscription_required
def dashboard():
    # Get user's campaigns
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, status, progress, successful_sends, failed_sends, total_recipients, created_at
        FROM campaigns WHERE user_id = ? ORDER BY created_at DESC LIMIT 10
    ''', (session['user_id'],))
    campaigns_data = cursor.fetchall()
    
    # Get subscription details
    cursor.execute('''
        SELECT subscription_status, trial_expires, subscription_expires, subscription_id, name
        FROM users WHERE id = ?
    ''', (session['user_id'],))
    user_data = cursor.fetchone()
    conn.close()
    
    # Calculate subscription info for display - FIXED LOGIC
    subscription_info = {
        'status': user_data[0] if user_data else 'inactive',
        'is_trial': False,  # Default to False
        'trial_ends_at': user_data[1] if user_data else None,
        'subscription_ends_at': user_data[2] if user_data else None,
        'has_subscription': bool(user_data[3]) if user_data else False,
        'user_name': user_data[4] if user_data else session.get('name', 'User')
    }
    
    # Only show trial banner if status is 'on_trial' AND trial hasn't expired
    if user_data and user_data[0] == 'on_trial' and user_data[1]:
        try:
            trial_end = datetime.fromisoformat(user_data[1])
            current_time = datetime.now()
            if trial_end > current_time:
                subscription_info['is_trial'] = True
                days_remaining = (trial_end - current_time).days
                subscription_info['days_remaining'] = days_remaining
        except:
            subscription_info['is_trial'] = False
    
    return render_template('dashboard.html', 
                         campaigns=campaigns_data, 
                         user_data=user_data,
                         subscription_info=subscription_info)



@app.route('/upload', methods=['POST'])
@subscription_required
def upload_csv():
    try:
        if 'csv_file' not in request.files:
            return jsonify({"error": "No CSV file uploaded"}), 400
        
        file = request.files['csv_file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        if not file.filename.lower().endswith('.csv'):
            return jsonify({"error": "File must be a CSV"}), 400
        
        df = pd.read_csv(file)
        columns = df.columns.tolist()
        
        if 'instagram_handle' not in columns:
            return jsonify({"error": "CSV must contain 'instagram_handle' column"}), 400
        
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{filename}")
        
        file.seek(0)
        file.save(filepath)
        
        return jsonify({
            "success": True,
            "file_id": file_id,
            "columns": columns,
            "row_count": len(df),
            "sample_data": df.head(3).to_dict('records')
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/start_campaign', methods=['POST'])
@subscription_required
def start_campaign():
    try:
        data = request.json
        
        required_fields = ['file_id', 'instagram_username', 'instagram_password', 'message_template']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        file_id = data['file_id']
        csv_file = None
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if filename.startswith(file_id):
                csv_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                break
        
        if not csv_file:
            return jsonify({"error": "CSV file not found"}), 404
        
        df = pd.read_csv(csv_file)
        
        campaign_id = str(uuid.uuid4())
        
        # Save campaign to database
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO campaigns (id, user_id, status, total_recipients, message_template)
            VALUES (?, ?, ?, ?, ?)
        ''', (campaign_id, session['user_id'], 'initializing', len(df), data['message_template']))
        conn.commit()
        conn.close()
        
        messenger = InstagramBulkMessenger(
            username=data['instagram_username'],
            password=data['instagram_password'],
            csv_data=df,
            message_template=data['message_template'],
            campaign_id=campaign_id,
            user_id=session['user_id']
        )
        
        thread = threading.Thread(target=messenger.run_campaign)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "success": True,
            "campaign_id": campaign_id,
            "message": "Campaign started successfully"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/campaign_status/<campaign_id>')
@login_required
def campaign_status(campaign_id):
    # Check if campaign belongs to user
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM campaigns WHERE id = ? AND user_id = ?', (campaign_id, session['user_id']))
    campaign = cursor.fetchone()
    conn.close()
    
    if not campaign:
        return jsonify({"error": "Campaign not found"}), 404
    
    # Get real-time status from memory if available
    if campaign_id in campaigns:
        return jsonify(campaigns[campaign_id])
    
    # Return database status
    return jsonify({
        "status": campaign[2],
        "progress": campaign[3],
        "results": {
            "successful": campaign[4],
            "failed": campaign[5],
            "total": campaign[6]
        }
    })

@app.route('/customer-portal')
@login_required
def customer_portal():
    """Redirect to Lemon Squeezy customer portal"""
    try:
        print(f"🔍 Customer portal accessed by user ID: {session['user_id']}")
        
        # Get user data
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT email, subscription_status, subscription_id 
            FROM users WHERE id = ?
        ''', (session['user_id'],))
        user_data = cursor.fetchone()
        conn.close()
        
        if not user_data:
            flash('User not found.', 'error')
            return redirect(url_for('pricing'))
        
        email, subscription_status, subscription_id = user_data
        
        if not subscription_id:
            flash('No active subscription found. Please subscribe first.', 'error')
            return redirect(url_for('pricing'))
        
        print(f"✅ Redirecting {email} to customer portal")
        
        # Direct redirect to Lemon Squeezy customer portal
        # Users will need to verify their email to access
        portal_url = f"https://app.lemonsqueezy.com/my-orders"
        
        flash('You will be redirected to manage your subscription. You may need to verify your email.', 'info')
        return redirect(portal_url)
        
    except Exception as e:
        print(f"❌ Customer portal error: {str(e)}")
        flash('Error accessing customer portal.', 'error')
        return redirect(url_for('subscription_management'))



@app.route('/subscription')
@login_required
def subscription_management():
    """Subscription management page"""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT subscription_status, subscription_expires, trial_expires, 
                   subscription_id, lemon_squeezy_customer_id, created_at, name
            FROM users WHERE id = ?
        ''', (session['user_id'],))
        user_data = cursor.fetchone()
        
        # Get subscription events
        cursor.execute('''
            SELECT event_type, created_at 
            FROM subscription_events 
            WHERE user_id = ? 
            ORDER BY created_at DESC LIMIT 10
        ''', (session['user_id'],))
        events = cursor.fetchall()
        
        conn.close()
        
        if not user_data:
            flash('User data not found.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('subscription.html', 
                             user_data=user_data, 
                             events=events)
                             
    except Exception as e:
        print(f"❌ Subscription management error: {e}")
        conn.close()
        flash('Error loading subscription data.', 'error')
        return redirect(url_for('dashboard'))




@app.route('/payment-success')
def payment_success():
    """Handle successful payment redirect from Lemon Squeezy"""
    if 'user_id' not in session:
        flash('Please log in to access your account.', 'info')
        return redirect(url_for('login'))
    
    flash('🎉 Payment successful! Your subscription is now active.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/payment-cancelled')
def payment_cancelled():
    """Handle cancelled payment"""
    flash('Payment was cancelled. You can try again anytime.', 'info')
    return redirect(url_for('pricing'))

@app.route('/callback')
def callback():
    try:
        print("🔍 Callback route accessed")
        
        NGROK_URL = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5000')
        
        flow = Flow.from_client_config(
            client_config,
            scopes=[
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ],
            redirect_uri=f"{NGROK_URL}/callback",
            state=session['state']
        )
        
        flow.fetch_token(authorization_response=request.url)
        
        credentials = flow.credentials
        request_session = google_requests.Request()
        
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            request_session,
            GOOGLE_CLIENT_ID
        )
        
        # Extract user information
        google_id = id_info['sub']
        email = id_info['email']
        name = id_info.get('name', '')
        picture = id_info.get('picture', '')
        
        print(f"✅ Google OAuth success - User: {name}, Email: {email}")
        
        # Database operations with detailed logging
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT id, subscription_status FROM users WHERE google_id = ? OR email = ?', (google_id, email))
        user = cursor.fetchone()
        
        if user:
            # Update existing user
            user_id = user[0]
            subscription_status = user[1]
            cursor.execute('''
                UPDATE users 
                SET google_id = ?, name = ?, picture = ?, email = ?
                WHERE id = ?
            ''', (google_id, name, picture, email, user_id))
            print(f"✅ Updated existing user {user_id}")
        else:
            # Create new user
            cursor.execute('''
                INSERT INTO users (email, google_id, name, picture, subscription_status)
                VALUES (?, ?, ?, ?, 'inactive')
            ''', (email, google_id, name, picture))
            user_id = cursor.lastrowid
            subscription_status = 'inactive'
            print(f"✅ Created new user {user_id}")
        
        conn.commit()
        
        # Verify user was created/updated
        cursor.execute('SELECT id, email, subscription_status FROM users WHERE id = ?', (user_id,))
        verify_user = cursor.fetchone()
        print(f"✅ User verification: ID={verify_user[0]}, Email={verify_user[1]}, Status={verify_user[2]}")
        
        conn.close()
        
        # Set session
        session.clear()
        session['user_id'] = user_id
        session['email'] = email
        session['name'] = name
        session['picture'] = picture
        session.permanent = True
        
        print(f"✅ Session set - User ID: {user_id}, Subscription: {subscription_status}")
        
        flash(f'Welcome {name}!', 'success')
        
        # Redirect based on subscription status
        if subscription_status in ['on_trial', 'active']:
            print("➡️ Redirecting to dashboard")
            return redirect(url_for('dashboard'))
        else:
            print("➡️ Redirecting to pricing")
            return redirect(url_for('pricing'))
        
    except Exception as e:
        print(f"❌ Callback error: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Login failed. Please try again.', 'error')
        return redirect(url_for('landing'))


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=3002)








