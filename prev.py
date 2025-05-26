# import os
# import time
# import random
# import pandas as pd
# import sqlite3
# import hashlib
# import secrets
# import hmac
# import json
# import threading
# import uuid
# from datetime import datetime, timedelta
# from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
# from werkzeug.utils import secure_filename
# from google_auth_oauthlib.flow import Flow
# from google.oauth2 import id_token
# from google.auth.transport import requests as google_requests
# import requests
# from functools import wraps
# from dotenv import load_dotenv

# # Selenium imports
# from selenium import webdriver
# from selenium.webdriver.common.by import By
# from selenium.webdriver.common.keys import Keys
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.chrome.options import Options
# from webdriver_manager.chrome import ChromeDriverManager
# from selenium.common.exceptions import NoSuchElementException, TimeoutException
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC

# # Load environment variables
# load_dotenv()

# app = Flask(__name__)
# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# app.config['UPLOAD_FOLDER'] = 'uploads'
# app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# # Google OAuth Configuration
# GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
# GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

# # Configure Google OAuth Flow
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development

# client_config = {
#     "web": {
#         "client_id": GOOGLE_CLIENT_ID,
#         "client_secret": GOOGLE_CLIENT_SECRET,
#         "auth_uri": "https://accounts.google.com/o/oauth2/auth",
#         "token_uri": "https://oauth2.googleapis.com/token",
#         "redirect_uris": ["http://localhost:5000/callback"]
#     }
# }

# # Ensure upload directory exists
# os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# # Store campaign status
# campaigns = {}

# # Initialize database
# def init_db():
#     conn = sqlite3.connect('app.db')
#     cursor = conn.cursor()
    
#     # Users table with Google OAuth
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS users (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             email TEXT UNIQUE NOT NULL,
#             google_id TEXT UNIQUE,
#             name TEXT,
#             picture TEXT,
#             subscription_status TEXT DEFAULT 'inactive',
#             subscription_id TEXT,
#             lemon_squeezy_customer_id TEXT,
#             subscription_expires TIMESTAMP,
#             trial_expires TIMESTAMP,
#             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#         )
#     ''')
    
#     # Campaigns table
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS campaigns (
#             id TEXT PRIMARY KEY,
#             user_id INTEGER,
#             status TEXT DEFAULT 'pending',
#             progress REAL DEFAULT 0,
#             successful_sends INTEGER DEFAULT 0,
#             failed_sends INTEGER DEFAULT 0,
#             total_recipients INTEGER DEFAULT 0,
#             message_template TEXT,
#             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#             completed_at TIMESTAMP,
#             FOREIGN KEY (user_id) REFERENCES users (id)
#         )
#     ''')
    
#     # Subscription events table
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS subscription_events (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             user_id INTEGER,
#             event_type TEXT NOT NULL,
#             lemon_squeezy_subscription_id TEXT,
#             event_data TEXT,
#             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#             FOREIGN KEY (user_id) REFERENCES users (id)
#         )
#     ''')
    
#     conn.commit()
#     conn.close()

# def migrate_database():
#     """Add missing columns to existing database"""
#     conn = sqlite3.connect('app.db')
#     cursor = conn.cursor()
    
#     try:
#         # Check and add missing columns
#         cursor.execute("PRAGMA table_info(users)")
#         columns = [column[1] for column in cursor.fetchall()]
        
#         if 'google_id' not in columns:
#             cursor.execute('ALTER TABLE users ADD COLUMN google_id TEXT UNIQUE')
#         if 'name' not in columns:
#             cursor.execute('ALTER TABLE users ADD COLUMN name TEXT')
#         if 'picture' not in columns:
#             cursor.execute('ALTER TABLE users ADD COLUMN picture TEXT')
#         if 'subscription_expires' not in columns:
#             cursor.execute('ALTER TABLE users ADD COLUMN subscription_expires TIMESTAMP')
#         if 'lemon_squeezy_customer_id' not in columns:
#             cursor.execute('ALTER TABLE users ADD COLUMN lemon_squeezy_customer_id TEXT')
#         if 'trial_expires' not in columns:
#             cursor.execute('ALTER TABLE users ADD COLUMN trial_expires TIMESTAMP')
            
#         conn.commit()
#         print("Database migration completed successfully!")
        
#     except Exception as e:
#         print(f"Migration error: {e}")
#         conn.rollback()
#     finally:
#         conn.close()

# init_db()
# migrate_database()

# def verify_webhook_signature(payload, signature, secret):
#     """Verify Lemon Squeezy webhook signature"""
#     if not signature or not secret:
#         return False
    
#     computed_hash = hmac.new(
#         secret.encode('utf-8'),
#         payload,
#         hashlib.sha256
#     )
#     expected_signature = computed_hash.hexdigest()
    
#     return hmac.compare_digest(expected_signature, signature)

# def login_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_id' not in session:
#             return redirect(url_for('login'))
#         return f(*args, **kwargs)
#     return decorated_function

# def subscription_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_id' not in session:
#             return redirect(url_for('login'))
        
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
#         cursor.execute('''
#             SELECT subscription_status, subscription_id, lemon_squeezy_customer_id 
#             FROM users WHERE id = ?
#         ''', (session['user_id'],))
#         user = cursor.fetchone()
#         conn.close()
        
#         if not user:
#             return redirect(url_for('login'))
        
#         subscription_status, subscription_id, customer_id = user
        
#         # Only allow access if user has a Lemon Squeezy subscription
#         if subscription_status in ['on_trial', 'active', 'cancelled', 'past_due'] and subscription_id:
#             return f(*args, **kwargs)
        
#         flash('🔒 Please subscribe to start your free trial and access InstaBulk Pro.', 'warning')
#         return redirect(url_for('pricing'))
    
#     return decorated_function

# # Instagram Automation Class
# class InstagramBulkMessenger:
#     def __init__(self, username, password, csv_data, message_template, campaign_id, user_id):
#         self.username = username
#         self.password = password
#         self.csv_data = csv_data
#         self.message_template = message_template
#         self.campaign_id = campaign_id
#         self.user_id = user_id
#         self.status = "initializing"
#         self.progress = 0
#         self.results = {"successful": 0, "failed": 0, "total": len(csv_data)}
        
#         # Setup Chrome options
#         chrome_options = Options()
#         chrome_options.add_argument("--no-sandbox")
#         chrome_options.add_argument("--disable-dev-shm-usage")
#         chrome_options.add_argument("--disable-blink-features=AutomationControlled")
#         chrome_options.add_argument("--headless")  # Run in headless mode for production
#         chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
#         chrome_options.add_experimental_option('useAutomationExtension', False)
        
#         self.driver = webdriver.Chrome(
#             service=Service(ChromeDriverManager().install()),
#             options=chrome_options
#         )
#         self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
#         self.wait = WebDriverWait(self.driver, 20)

#     def human_type(self, element, text, delay_range=(0.1, 0.3)):
#         for char in text:
#             element.send_keys(char)
#             time.sleep(random.uniform(*delay_range))

#     def personalize_message(self, row):
#         message = self.message_template
#         for column, value in row.items():
#             placeholder = "{" + str(column) + "}"
#             message = message.replace(placeholder, str(value))
#         return message

#     def handle_popup_screens(self):
#         popup_handlers = [
#             ("//button[contains(text(), 'Not Now')]", "Notifications popup"),
#             ("//button[text()='Not Now']", "Notifications popup (exact match)"),
#             ("//button[contains(text(), 'Not now')]", "Save login info popup"),
#             ("//button[text()='Not now']", "Save login info popup (exact match)"),
#             ("//button[contains(text(), 'Cancel')]", "Add to home screen popup"),
#         ]
        
#         for xpath, description in popup_handlers:
#             try:
#                 popup_button = WebDriverWait(self.driver, 3).until(
#                     EC.element_to_be_clickable((By.XPATH, xpath))
#                 )
#                 popup_button.click()
#                 time.sleep(random.uniform(2, 4))
#             except (NoSuchElementException, TimeoutException):
#                 continue

#     def login(self):
#         try:
#             self.status = "logging_in"
#             self.update_campaign_status()
            
#             self.driver.get('https://www.instagram.com/accounts/login/')
#             time.sleep(random.uniform(5, 8))
            
#             username_input = self.wait.until(
#                 EC.presence_of_element_located((By.NAME, 'username'))
#             )
#             time.sleep(random.uniform(1, 2))
#             self.human_type(username_input, self.username)
            
#             time.sleep(random.uniform(1, 3))
            
#             password_input = self.driver.find_element(By.NAME, 'password')
#             self.human_type(password_input, self.password)
            
#             time.sleep(random.uniform(2, 4))
#             password_input.send_keys(Keys.RETURN)
            
#             time.sleep(random.uniform(8, 12))
#             self.handle_popup_screens()
#             time.sleep(random.uniform(3, 6))
            
#             try:
#                 self.wait.until(
#                     EC.any_of(
#                         EC.presence_of_element_located((By.XPATH, "//a[@href='/']")),
#                         EC.presence_of_element_located((By.XPATH, "//svg[@aria-label='Home']")),
#                         EC.presence_of_element_located((By.XPATH, "//span[text()='Home']"))
#                     )
#                 )
#                 return True
#             except TimeoutException:
#                 return False
                
#         except Exception as e:
#             return False

#     def send_message(self, instagram_handle, personalized_message):
#         try:
#             profile_url = f'https://www.instagram.com/{instagram_handle}/'
#             self.driver.get(profile_url)
#             time.sleep(random.uniform(5, 8))
            
#             message_button_selectors = [
#                 "//div[text()='Message']",
#                 "//button[text()='Message']",
#                 "//div[@role='button'][contains(text(), 'Message')]",
#                 "//button[contains(text(), 'Message')]"
#             ]
            
#             message_button_found = False
#             for selector in message_button_selectors:
#                 try:
#                     message_button = self.wait.until(
#                         EC.element_to_be_clickable((By.XPATH, selector))
#                     )
#                     self.driver.execute_script("arguments[0].scrollIntoView(true);", message_button)
#                     time.sleep(random.uniform(1, 2))
#                     message_button.click()
#                     time.sleep(random.uniform(4, 7))
#                     message_button_found = True
#                     break
#                 except (NoSuchElementException, TimeoutException):
#                     continue
            
#             if not message_button_found:
#                 return False
            
#             try:
#                 not_now_button = WebDriverWait(self.driver, 5).until(
#                     EC.element_to_be_clickable((By.XPATH, "//button[text()='Not Now']"))
#                 )
#                 not_now_button.click()
#                 time.sleep(random.uniform(2, 4))
#             except TimeoutException:
#                 pass
            
#             message_input_selectors = [
#                 "//textarea[@placeholder='Message...']",
#                 "//div[@contenteditable='true'][@data-lexical-editor='true']",
#                 "//div[@contenteditable='true'][contains(@aria-label, 'Message')]",
#                 "//div[@role='textbox']"
#             ]
            
#             for selector in message_input_selectors:
#                 try:
#                     message_input = self.wait.until(
#                         EC.element_to_be_clickable((By.XPATH, selector))
#                     )
#                     message_input.click()
#                     time.sleep(random.uniform(1, 2))
#                     message_input.clear()
#                     time.sleep(random.uniform(0.5, 1))
                    
#                     self.human_type(message_input, personalized_message, delay_range=(0.05, 0.15))
#                     time.sleep(random.uniform(2, 4))
                    
#                     message_input.send_keys(Keys.RETURN)
#                     time.sleep(random.uniform(3, 6))
#                     return True
                    
#                 except (NoSuchElementException, TimeoutException):
#                     continue
            
#             return False
            
#         except Exception as e:
#             return False

#     def update_campaign_status(self):
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
#         cursor.execute('''
#             UPDATE campaigns 
#             SET status = ?, progress = ?, successful_sends = ?, failed_sends = ?
#             WHERE id = ?
#         ''', (self.status, self.progress, self.results["successful"], self.results["failed"], self.campaign_id))
#         conn.commit()
#         conn.close()
        
#         campaigns[self.campaign_id] = {
#             "status": self.status,
#             "progress": self.progress,
#             "results": self.results
#         }

#     def run_campaign(self):
#         try:
#             if not self.login():
#                 self.status = "login_failed"
#                 self.update_campaign_status()
#                 return
            
#             self.status = "sending_messages"
#             self.update_campaign_status()
            
#             for index, row in self.csv_data.iterrows():
#                 instagram_handle = row.get('instagram_handle', '')
#                 if not instagram_handle:
#                     self.results["failed"] += 1
#                     continue
                
#                 personalized_message = self.personalize_message(row)
                
#                 if self.send_message(instagram_handle, personalized_message):
#                     self.results["successful"] += 1
#                 else:
#                     self.results["failed"] += 1
                
#                 self.progress = ((index + 1) / len(self.csv_data)) * 100
#                 self.update_campaign_status()
                
#                 if index < len(self.csv_data) - 1:
#                     delay = random.randint(60, 150)
#                     time.sleep(delay)
            
#             self.status = "completed"
#             self.update_campaign_status()
            
#             # Update database with completion
#             conn = sqlite3.connect('app.db')
#             cursor = conn.cursor()
#             cursor.execute('UPDATE campaigns SET completed_at = ? WHERE id = ?', 
#                          (datetime.now().isoformat(), self.campaign_id))
#             conn.commit()
#             conn.close()
            
#         except Exception as e:
#             self.status = "error"
#             self.update_campaign_status()
#         finally:
#             self.driver.quit()

# # Routes
# @app.route('/')
# def landing():
#     return render_template('landing.html')

# @app.route('/login')
# def login():
#     if 'user_id' in session:
#         return redirect(url_for('dashboard'))
    
#     flow = Flow.from_client_config(
#         client_config,
#         scopes=['openid', 'email', 'profile'],
#         redirect_uri=url_for('callback', _external=True)
#     )
    
#     authorization_url, state = flow.authorization_url(
#         access_type='offline',
#         include_granted_scopes='true'
#     )
    
#     session['state'] = state
#     return redirect(authorization_url)

# @app.route('/callback')
# def callback():
#     try:
#         flow = Flow.from_client_config(
#             client_config,
#             scopes=['openid', 'email', 'profile'],
#             redirect_uri=url_for('callback', _external=True),
#             state=session['state']
#         )
        
#         flow.fetch_token(authorization_response=request.url)
        
#         credentials = flow.credentials
#         request_session = google_requests.Request()
        
#         id_info = id_token.verify_oauth2_token(
#             credentials.id_token,
#             request_session,
#             GOOGLE_CLIENT_ID
#         )
        
#         # Extract user information
#         google_id = id_info['sub']
#         email = id_info['email']
#         name = id_info.get('name', '')
#         picture = id_info.get('picture', '')
        
#         # Check if user exists or create new user
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
        
#         cursor.execute('SELECT id, subscription_status FROM users WHERE google_id = ? OR email = ?', (google_id, email))
#         user = cursor.fetchone()
        
#         if user:
#             # Update existing user
#             user_id = user[0]
#             cursor.execute('''
#                 UPDATE users 
#                 SET google_id = ?, name = ?, picture = ?, email = ?
#                 WHERE id = ?
#             ''', (google_id, name, picture, email, user_id))
#         else:
#             # Create new user
#             cursor.execute('''
#                 INSERT INTO users (email, google_id, name, picture, subscription_status)
#                 VALUES (?, ?, ?, ?, 'inactive')
#             ''', (email, google_id, name, picture))
#             user_id = cursor.lastrowid
        
#         conn.commit()
#         conn.close()
        
#         # Set session
#         session['user_id'] = user_id
#         session['email'] = email
#         session['name'] = name
#         session['picture'] = picture
        
#         flash(f'Welcome {name}!', 'success')
        
#         # Check subscription status and redirect accordingly
#         if user and user[1] in ['on_trial', 'active']:
#             return redirect(url_for('dashboard'))
#         else:
#             return redirect(url_for('pricing'))
        
#     except Exception as e:
#         flash('Login failed. Please try again.', 'error')
#         return redirect(url_for('landing'))

# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out.', 'info')
#     return redirect(url_for('landing'))

# @app.route('/pricing')
# def pricing():
#     return render_template('pricing.html')

# @app.route('/create-checkout', methods=['POST'])
# @login_required
# def create_checkout():
#     try:
#         api_key = os.environ.get('LEMON_SQUEEZY_API_KEY')
        
#         if not api_key:
#             return jsonify({'error': 'API key not configured'}), 500
        
#         headers = {
#             'Authorization': f'Bearer {api_key}',
#             'Content-Type': 'application/vnd.api+json',
#             'Accept': 'application/vnd.api+json'
#         }
        
#         # Set redirect URL to payment success page
#         redirect_url = request.url_root.rstrip('/') + '/payment-success'
        
#         data = {
#             'data': {
#                 'type': 'checkouts',
#                 'attributes': {
#                     'checkout_data': {
#                         'email': session['email'],
#                         'name': session.get('name', session['email']),
#                         'custom': {
#                             'user_id': str(session['user_id']),
#                             'user_email': session['email']
#                         }
#                     },
#                     'checkout_options': {
#                         'embed': False,
#                         'media': False,
#                         'logo': True,
#                         'desc': True,
#                         'discount': True,
#                         'dark': False,
#                         'subscription_preview': True,
#                         'button_color': '#6366f1'
#                     },
#                     'product_options': {
#                         'enabled_variants': [int(os.environ.get('LEMON_SQUEEZY_VARIANT_ID'))],
#                         'redirect_url': redirect_url,
#                         'receipt_button_text': 'Access Dashboard',
#                         'receipt_link_url': redirect_url,
#                         'receipt_thank_you_note': 'Welcome to InstaBulk Pro! Your 7-day free trial has started.'
#                     }
#                 },
#                 'relationships': {
#                     'store': {
#                         'data': {
#                             'type': 'stores',
#                             'id': str(os.environ.get('LEMON_SQUEEZY_STORE_ID'))
#                         }
#                     },
#                     'variant': {
#                         'data': {
#                             'type': 'variants',
#                             'id': str(os.environ.get('LEMON_SQUEEZY_VARIANT_ID'))
#                         }
#                     }
#                 }
#             }
#         }
        
#         print(f"Creating checkout for user {session['user_id']} with email {session['email']}")
        
#         response = requests.post(
#             'https://api.lemonsqueezy.com/v1/checkouts',
#             headers=headers,
#             json=data
#         )
        
#         if response.status_code == 201:
#             checkout_data = response.json()
#             checkout_url = checkout_data['data']['attributes']['url']
#             return jsonify({'checkout_url': checkout_url})
#         else:
#             print(f"Lemon Squeezy Error: {response.status_code} - {response.text}")
#             return jsonify({'error': 'Failed to create checkout'}), 500
            
#     except Exception as e:
#         print(f"Exception in checkout: {str(e)}")
#         return jsonify({'error': str(e)}), 500

# @app.route('/payment-success')
# def payment_success():
#     """Handle successful payment redirect from Lemon Squeezy"""
#     if 'user_id' not in session:
#         flash('Please log in to access your account.', 'info')
#         return redirect(url_for('login'))
    
#     flash('🎉 Welcome to InstaBulk Pro! Your subscription is now active.', 'success')
#     return redirect(url_for('dashboard'))

# @app.route('/upload', methods=['POST'])
# @subscription_required
# def upload_csv():
#     try:
#         if 'csv_file' not in request.files:
#             return jsonify({"error": "No CSV file uploaded"}), 400
        
#         file = request.files['csv_file']
#         if file.filename == '':
#             return jsonify({"error": "No file selected"}), 400
        
#         if not file.filename.lower().endswith('.csv'):
#             return jsonify({"error": "File must be a CSV"}), 400
        
#         df = pd.read_csv(file)
#         columns = df.columns.tolist()
        
#         if 'instagram_handle' not in columns:
#             return jsonify({"error": "CSV must contain 'instagram_handle' column"}), 400
        
#         filename = secure_filename(file.filename)
#         file_id = str(uuid.uuid4())
#         filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{filename}")
        
#         file.seek(0)
#         file.save(filepath)
        
#         return jsonify({
#             "success": True,
#             "file_id": file_id,
#             "columns": columns,
#             "row_count": len(df),
#             "sample_data": df.head(3).to_dict('records')
#         })
        
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# @app.route('/start_campaign', methods=['POST'])
# @subscription_required
# def start_campaign():
#     try:
#         data = request.json
        
#         required_fields = ['file_id', 'instagram_username', 'instagram_password', 'message_template']
#         for field in required_fields:
#             if field not in data:
#                 return jsonify({"error": f"Missing required field: {field}"}), 400
        
#         file_id = data['file_id']
#         csv_file = None
#         for filename in os.listdir(app.config['UPLOAD_FOLDER']):
#             if filename.startswith(file_id):
#                 csv_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#                 break
        
#         if not csv_file:
#             return jsonify({"error": "CSV file not found"}), 404
        
#         df = pd.read_csv(csv_file)
        
#         campaign_id = str(uuid.uuid4())
        
#         # Save campaign to database
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
#         cursor.execute('''
#             INSERT INTO campaigns (id, user_id, status, total_recipients, message_template)
#             VALUES (?, ?, ?, ?, ?)
#         ''', (campaign_id, session['user_id'], 'initializing', len(df), data['message_template']))
#         conn.commit()
#         conn.close()
        
#         messenger = InstagramBulkMessenger(
#             username=data['instagram_username'],
#             password=data['instagram_password'],
#             csv_data=df,
#             message_template=data['message_template'],
#             campaign_id=campaign_id,
#             user_id=session['user_id']
#         )
        
#         thread = threading.Thread(target=messenger.run_campaign)
#         thread.daemon = True
#         thread.start()
        
#         return jsonify({
#             "success": True,
#             "campaign_id": campaign_id,
#             "message": "Campaign started successfully"
#         })
        
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# @app.route('/campaign_status/<campaign_id>')
# @login_required
# def campaign_status(campaign_id):
#     # Check if campaign belongs to user
#     conn = sqlite3.connect('app.db')
#     cursor = conn.cursor()
#     cursor.execute('SELECT * FROM campaigns WHERE id = ? AND user_id = ?', (campaign_id, session['user_id']))
#     campaign = cursor.fetchone()
#     conn.close()
    
#     if not campaign:
#         return jsonify({"error": "Campaign not found"}), 404
    
#     # Get real-time status from memory if available
#     if campaign_id in campaigns:
#         return jsonify(campaigns[campaign_id])
    
#     # Return database status
#     return jsonify({
#         "status": campaign[2],
#         "progress": campaign[3],
#         "results": {
#             "successful": campaign[4],
#             "failed": campaign[5],
#             "total": campaign[6]
#         }
#     })

# @app.route('/webhook', methods=['POST'])
# def webhook():
#     """Handle Lemon Squeezy webhooks with improved user matching"""
#     try:
#         # Get the raw payload
#         payload = request.get_data()
#         signature = request.headers.get('X-Signature')
        
#         # Verify webhook signature
#         if not verify_webhook_signature(payload, signature, os.environ.get('LEMON_SQUEEZY_WEBHOOK_SECRET')):
#             print("❌ Invalid webhook signature")
#             return jsonify({'error': 'Invalid signature'}), 401
        
#         # Parse the JSON payload
#         event_data = json.loads(payload.decode('utf-8'))
#         event_name = event_data['meta']['event_name']
        
#         print(f"✅ Verified webhook: {event_name}")
        
#         if event_name == 'subscription_created':
#             handle_subscription_created(event_data)
#         elif event_name == 'subscription_updated':
#             handle_subscription_updated(event_data)
#         elif event_name == 'subscription_cancelled':
#             handle_subscription_cancelled(event_data)
#         elif event_name == 'subscription_resumed':
#             handle_subscription_resumed(event_data)
#         elif event_name == 'subscription_expired':
#             handle_subscription_expired(event_data)
        
#         return jsonify({'status': 'success'})
        
#     except Exception as e:
#         print(f"Webhook error: {str(e)}")
#         return jsonify({'error': str(e)}), 500

# def handle_subscription_created(event_data):
#     """Handle new subscription creation with improved user matching"""
#     try:
#         subscription = event_data['data']
#         attributes = subscription['attributes']
        
#         # Get user identification from multiple sources
#         custom_data = attributes.get('custom_data', {})
#         user_id = custom_data.get('user_id')
#         user_email = custom_data.get('user_email') or attributes.get('user_email')
#         customer_email = attributes.get('customer_email')
        
#         print(f"🔍 Subscription created - User ID: {user_id}, Email: {user_email or customer_email}")
        
#         # Find user by multiple methods
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
        
#         target_user_id = None
        
#         # Method 1: Direct user_id match
#         if user_id:
#             cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
#             result = cursor.fetchone()
#             if result:
#                 target_user_id = result[0]
#                 print(f"✅ Found user by ID: {target_user_id}")
        
#         # Method 2: Email match
#         if not target_user_id and (user_email or customer_email):
#             email_to_search = user_email or customer_email
#             cursor.execute('SELECT id FROM users WHERE email = ?', (email_to_search,))
#             result = cursor.fetchone()
#             if result:
#                 target_user_id = result[0]
#                 print(f"✅ Found user by email: {target_user_id}")
        
#         if not target_user_id:
#             print(f"❌ No user found for subscription {subscription['id']}")
#             conn.close()
#             return
        
#         # Update user subscription
#         subscription_id = subscription['id']
#         customer_id = attributes['customer_id']
#         status = attributes['status']
#         trial_ends_at = attributes.get('trial_ends_at')
#         ends_at = attributes['ends_at']
        
#         cursor.execute('''
#             UPDATE users 
#             SET subscription_status = ?, 
#                 subscription_id = ?,
#                 lemon_squeezy_customer_id = ?,
#                 subscription_expires = ?,
#                 trial_expires = ?
#             WHERE id = ?
#         ''', (status, subscription_id, customer_id, ends_at, trial_ends_at, target_user_id))
        
#         # Log the event
#         cursor.execute('''
#             INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
#             VALUES (?, ?, ?, ?)
#         ''', (target_user_id, 'subscription_created', subscription_id, json.dumps(event_data)))
        
#         conn.commit()
#         conn.close()
        
#         print(f"✅ Subscription {subscription_id} created for user {target_user_id} with status: {status}")
        
#     except Exception as e:
#         print(f"❌ Error handling subscription_created: {str(e)}")

# def handle_subscription_updated(event_data):
#     """Handle subscription updates"""
#     try:
#         subscription = event_data['data']
#         subscription_id = subscription['id']
#         status = subscription['attributes']['status']
#         ends_at = subscription['attributes']['ends_at']
#         trial_ends_at = subscription['attributes'].get('trial_ends_at')
        
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
        
#         # Update subscription status
#         cursor.execute('''
#             UPDATE users 
#             SET subscription_status = ?,
#                 subscription_expires = ?,
#                 trial_expires = ?
#             WHERE subscription_id = ?
#         ''', (status, ends_at, trial_ends_at, subscription_id))
        
#         # Log the event
#         cursor.execute('''
#             INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
#             VALUES ((SELECT id FROM users WHERE subscription_id = ?), ?, ?, ?)
#         ''', (subscription_id, 'subscription_updated', subscription_id, json.dumps(event_data)))
        
#         conn.commit()
#         conn.close()
        
#         print(f"✅ Subscription {subscription_id} updated to {status}")
        
#     except Exception as e:
#         print(f"❌ Error handling subscription_updated: {str(e)}")

# def handle_subscription_cancelled(event_data):
#     """Handle subscription cancellation"""
#     try:
#         subscription = event_data['data']
#         subscription_id = subscription['id']
        
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
        
#         cursor.execute('''
#             UPDATE users 
#             SET subscription_status = 'cancelled'
#             WHERE subscription_id = ?
#         ''', (subscription_id,))
        
#         cursor.execute('''
#             INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
#             VALUES ((SELECT id FROM users WHERE subscription_id = ?), ?, ?, ?)
#         ''', (subscription_id, 'subscription_cancelled', subscription_id, json.dumps(event_data)))
        
#         conn.commit()
#         conn.close()
        
#         print(f"✅ Subscription {subscription_id} cancelled")
        
#     except Exception as e:
#         print(f"❌ Error handling subscription_cancelled: {str(e)}")

# def handle_subscription_resumed(event_data):
#     """Handle subscription resumption"""
#     try:
#         subscription = event_data['data']
#         subscription_id = subscription['id']
        
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
        
#         cursor.execute('''
#             UPDATE users 
#             SET subscription_status = 'active'
#             WHERE subscription_id = ?
#         ''', (subscription_id,))
        
#         cursor.execute('''
#             INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
#             VALUES ((SELECT id FROM users WHERE subscription_id = ?), ?, ?, ?)
#         ''', (subscription_id, 'subscription_resumed', subscription_id, json.dumps(event_data)))
        
#         conn.commit()
#         conn.close()
        
#         print(f"✅ Subscription {subscription_id} resumed")
        
#     except Exception as e:
#         print(f"❌ Error handling subscription_resumed: {str(e)}")

# def handle_subscription_expired(event_data):
#     """Handle subscription expiration"""
#     try:
#         subscription = event_data['data']
#         subscription_id = subscription['id']
        
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
        
#         cursor.execute('''
#             UPDATE users 
#             SET subscription_status = 'expired'
#             WHERE subscription_id = ?
#         ''', (subscription_id,))
        
#         cursor.execute('''
#             INSERT INTO subscription_events (user_id, event_type, lemon_squeezy_subscription_id, event_data)
#             VALUES ((SELECT id FROM users WHERE subscription_id = ?), ?, ?, ?)
#         ''', (subscription_id, 'subscription_expired', subscription_id, json.dumps(event_data)))
        
#         conn.commit()
#         conn.close()
        
#         print(f"✅ Subscription {subscription_id} expired")
        
#     except Exception as e:
#         print(f"❌ Error handling subscription_expired: {str(e)}")

# @app.route('/dashboard')
# @subscription_required
# def dashboard():
#     # Get user's campaigns
#     conn = sqlite3.connect('app.db')
#     cursor = conn.cursor()
#     cursor.execute('''
#         SELECT id, status, progress, successful_sends, failed_sends, total_recipients, created_at
#         FROM campaigns WHERE user_id = ? ORDER BY created_at DESC LIMIT 10
#     ''', (session['user_id'],))
#     campaigns_data = cursor.fetchall()
    
#     # Get subscription details
#     cursor.execute('''
#         SELECT subscription_status, trial_expires, subscription_expires, subscription_id, name
#         FROM users WHERE id = ?
#     ''', (session['user_id'],))
#     user_data = cursor.fetchone()
#     conn.close()
    
#     # Calculate subscription info for display
#     subscription_info = {
#         'status': user_data[0] if user_data else 'inactive',
#         'is_trial': user_data[0] == 'on_trial',
#         'trial_ends_at': user_data[1],
#         'subscription_ends_at': user_data[2],
#         'has_subscription': bool(user_data[3]),
#         'user_name': user_data[4] if user_data else session.get('name', 'User')
#     }
    
#     return render_template('dashboard.html', 
#                          campaigns=campaigns_data, 
#                          user_data=user_data,
#                          subscription_info=subscription_info)

# @app.route('/subscription')
# @login_required
# def subscription_management():
#     """Subscription management page"""
#     conn = sqlite3.connect('app.db')
#     cursor = conn.cursor()
#     cursor.execute('''
#         SELECT subscription_status, subscription_expires, trial_expires, 
#                subscription_id, lemon_squeezy_customer_id, created_at, name
#         FROM users WHERE id = ?
#     ''', (session['user_id'],))
#     user_data = cursor.fetchone()
    
#     # Get subscription events
#     cursor.execute('''
#         SELECT event_type, created_at 
#         FROM subscription_events 
#         WHERE user_id = ? 
#         ORDER BY created_at DESC LIMIT 10
#     ''', (session['user_id'],))
#     events = cursor.fetchall()
    
#     conn.close()
    
#     return render_template('subscription.html', 
#                          user_data=user_data, 
#                          events=events)

# @app.route('/customer-portal')
# @login_required
# def customer_portal():
#     """Redirect to Lemon Squeezy customer portal"""
#     try:
#         conn = sqlite3.connect('app.db')
#         cursor = conn.cursor()
#         cursor.execute('''
#             SELECT lemon_squeezy_customer_id FROM users WHERE id = ?
#         ''', (session['user_id'],))
#         result = cursor.fetchone()
#         conn.close()
        
#         if not result or not result[0]:
#             flash('No active subscription found. Please subscribe first.', 'error')
#             return redirect(url_for('pricing'))
        
#         customer_id = result[0]
        
#         headers = {
#             'Authorization': f'Bearer {os.environ.get("LEMON_SQUEEZY_API_KEY")}',
#             'Content-Type': 'application/vnd.api+json',
#         }
        
#         data = {
#             'data': {
#                 'type': 'customer-portal',
#                 'attributes': {
#                     'customer_id': customer_id
#                 }
#             }
#         }
        
#         response = requests.post(
#             'https://api.lemonsqueezy.com/v1/customer-portal',
#             headers=headers,
#             json=data
#         )
        
#         if response.status_code == 201:
#             portal_data = response.json()
#             portal_url = portal_data['data']['attributes']['url']
#             return redirect(portal_url)
#         else:
#             flash('Unable to access customer portal. Please try again later.', 'error')
#             return redirect(url_for('subscription_management'))
            
#     except Exception as e:
#         flash('Error accessing customer portal.', 'error')
#         return redirect(url_for('subscription_management'))

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=3002)
