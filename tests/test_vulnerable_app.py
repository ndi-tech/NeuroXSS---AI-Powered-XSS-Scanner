#!/usr/bin/env python3
"""
Intentionally vulnerable Flask application for testing the scanner
"""

from flask import Flask, request, render_template_string, make_response
import html

app = Flask(__name__)

# HTML templates
INDEX_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Test Vulnerable App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .vulnerable { border-left: 4px solid #dc3545; padding: 15px; background: #fff5f5; margin: 20px 0; }
        .safe { border-left: 4px solid #28a745; padding: 15px; background: #f0fff4; margin: 20px 0; }
        input[type=text], textarea { width: 100%; padding: 8px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        input[type=submit] { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        input[type=submit]:hover { background: #0056b3; }
        .warning { color: #dc3545; font-weight: bold; }
        .info { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Test Vulnerable Application</h1>
        <p class="info">This app contains intentional vulnerabilities for testing security scanners.</p>
        
        <div class="vulnerable">
            <h3>⚠️ Reflected XSS (Vulnerable)</h3>
            <form method="GET" action="/search">
                <input type="text" name="q" placeholder="Search query...">
                <input type="submit" value="Search">
            </form>
        </div>
        
        <div class="vulnerable">
            <h3>⚠️ Stored XSS (Vulnerable)</h3>
            <form method="POST" action="/comment">
                <textarea name="comment" placeholder="Leave a comment..." rows="3"></textarea>
                <input type="submit" value="Post Comment">
            </form>
        </div>
        
        <div class="safe">
            <h3>✅ Safe Form (Protected)</h3>
            <form method="GET" action="/safe">
                <input type="text" name="input" placeholder="Safe input...">
                <input type="submit" value="Submit">
            </form>
        </div>
        
        <div class="vulnerable">
            <h3>⚠️ DOM-based XSS (Vulnerable)</h3>
            <input type="text" id="domInput" placeholder="Enter text...">
            <button onclick="updateDOM()">Update</button>
            <div id="output"></div>
            <script>
                function updateDOM() {
                    var input = document.getElementById('domInput').value;
                    document.getElementById('output').innerHTML = input;
                }
            </script>
        </div>
        
        <div class="vulnerable">
            <h3>⚠️ JavaScript Context XSS (Vulnerable)</h3>
            <form method="GET" action="/js-context">
                <input type="text" name="callback" placeholder="Callback name...">
                <input type="submit" value="Execute">
            </form>
        </div>
        
        <div class="vulnerable">
            <h3>⚠️ Attribute XSS (Vulnerable)</h3>
            <form method="GET" action="/attribute">
                <input type="text" name="color" placeholder="Color...">
                <input type="submit" value="Set Color">
            </form>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return INDEX_HTML

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # INTENTIONAL VULNERABILITY: Raw reflection
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results for: {query}</h1>
        <p>Found 0 results.</p>
        <a href="/">Back</a>
    </body>
    </html>
    ''')

@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form.get('comment', '')
    # Store in memory (simulated stored XSS)
    if not hasattr(app, 'comments'):
        app.comments = []
    app.comments.append(comment)
    
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head><title>Comments</title></head>
    <body>
        <h1>All Comments</h1>
        {''.join(f'<div>{c}</div>' for c in app.comments)}
        <a href="/">Back</a>
    </body>
    </html>
    ''')

@app.route('/safe')
def safe():
    user_input = request.args.get('input', '')
    # PROTECTED: HTML escaped
    safe_input = html.escape(user_input)
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head><title>Safe Output</title></head>
    <body>
        <h1>You entered: {safe_input}</h1>
        <a href="/">Back</a>
    </body>
    </html>
    ''')

@app.route('/js-context')
def js_context():
    callback = request.args.get('callback', 'defaultCallback')
    # INTENTIONAL VULNERABILITY: In script context
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>JavaScript Context</title>
        <script>
            function {callback}() {{
                alert('Callback executed');
            }}
            window.onload = {callback};
        </script>
    </head>
    <body>
        <h1>JavaScript Context Test</h1>
        <a href="/">Back</a>
    </body>
    </html>
    ''')

@app.route('/attribute')
def attribute():
    color = request.args.get('color', 'black')
    # INTENTIONAL VULNERABILITY: In HTML attribute
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attribute Context</title>
        <style>
            body {{ color: {color}; }}
        </style>
    </head>
    <body>
        <h1>Attribute Context Test</h1>
        <p>Your color: {color}</p>
        <a href="/">Back</a>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    print("=" * 60)
    print("🚨 WARNING: Intentionally Vulnerable Test Application")
    print("🚨 DO NOT deploy this in production!")
    print("=" * 60)
    print("\nStarting test server on http://localhost:8080")
    app.run(debug=True, host='0.0.0.0', port=8080)