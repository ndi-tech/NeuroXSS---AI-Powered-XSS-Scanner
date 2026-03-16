# test_app.py
from flask import Flask, request
import webbrowser
import threading
import time

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>NeuroXSS Test App</title>
        <style>
            body { font-family: Arial; margin: 40px; line-height: 1.6; }
            .container { max-width: 800px; margin: 0 auto; }
            .form-box { border: 1px solid #ddd; padding: 20px; margin: 20px 0; border-radius: 5px; }
            input[type="text"] { width: 300px; padding: 8px; margin: 10px 0; }
            input[type="submit"] { padding: 10px 20px; background: #4CAF50; color: white; border: none; cursor: pointer; }
            .warning { background: #ffeb3b; padding: 10px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ NeuroXSS Test Application</h1>
            <div class="warning">
                <strong>⚠️ WARNING:</strong> This app is intentionally vulnerable for testing!
            </div>
            
            <div class="form-box">
                <h2>Test Form 1 - Basic XSS</h2>
                <form method="POST" action="/reflect">
                    <input type="text" name="input" placeholder="Enter any text">
                    <input type="submit" value="Submit">
                </form>
                <small>This form reflects input without encoding - vulnerable to XSS</small>
            </div>
            
            <div class="form-box">
                <h2>Test Form 2 - GET Parameter</h2>
                <form method="GET" action="/search">
                    <input type="text" name="q" placeholder="Search...">
                    <input type="submit" value="Search">
                </form>
                <small>URL parameter reflection - vulnerable to XSS</small>
            </div>
            
            <div class="form-box">
                <h2>Test Form 3 - Multiple Parameters</h2>
                <form method="POST" action="/comment">
                    <input type="text" name="name" placeholder="Your name"><br>
                    <input type="text" name="comment" placeholder="Your comment"><br>
                    <input type="submit" value="Post Comment">
                </form>
                <small>Multiple input fields - all vulnerable</small>
            </div>
            
            <div class="form-box">
                <h2>Test Form 4 - With Basic Filter</h2>
                <form method="GET" action="/filtered">
                    <input type="text" name="search" placeholder="Search (basic filter)">
                    <input type="submit" value="Search">
                </form>
                <small>Has basic filter - good for testing AI detection</small>
            </div>
            
            <p>Try entering: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
        </div>
    </body>
    </html>
    '''

@app.route('/reflect', methods=['POST'])
def reflect():
    user_input = request.form.get('input', '')
    # VULNERABLE: Direct reflection without encoding
    return f'''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>You entered:</h2>
        <div style="border: 1px solid #ddd; padding: 20px; margin: 20px 0;">
            {user_input}
        </div>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: URL parameter reflection
    return f'''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>Search results for: "{query}"</h2>
        <p>No results found.</p>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

@app.route('/comment', methods=['POST'])
def comment():
    name = request.form.get('name', '')
    comment = request.form.get('comment', '')
    # VULNERABLE: Multiple parameter reflection
    return f'''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>Comment posted!</h2>
        <div style="border: 1px solid #ddd; padding: 20px;">
            <strong>{name}</strong> said:<br>
            {comment}
        </div>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

@app.route('/filtered')
def filtered():
    search = request.args.get('search', '')
    
    # Basic filter (simulates simple WAF)
    blocked = ['script', 'alert', 'onerror']
    filtered_search = search
    for term in blocked:
        if term in search.lower():
            filtered_search = "[FILTERED]"
            break
    
    # Still vulnerable if filter can be bypassed
    return f'''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>Filtered search results for: "{filtered_search}"</h2>
        <p>Basic filtering applied.</p>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

def open_browser():
    """Open browser after a short delay"""
    time.sleep(1.5)
    webbrowser.open('http://localhost:5000')

if __name__ == '__main__':
    print("\n" + "="*60)
    print("NEUROXSS TEST APPLICATION")
    print("="*60)
    print("Starting vulnerable test app on http://localhost:5000")
    print("\nThis app contains intentional XSS vulnerabilities for testing!")
    print("\nPress Ctrl+C to stop the server")
    print("="*60 + "\n")
    
    # Open browser automatically
    threading.Thread(target=open_browser).start()
    
    # Run the app
    app.run(debug=True, port=5000)