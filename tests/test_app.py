# tests/test_app.py
from flask import Flask, request, render_template_string
import html

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <html>
    <head><title>NeuroXSS Test App</title></head>
    <body>
        <h1>NeuroXSS Vulnerability Test Application</h1>
        
        <h2>Test Form 1 - Reflected XSS</h2>
        <form method="POST" action="/reflected">
            <input type="text" name="input" placeholder="Enter text">
            <input type="submit" value="Submit">
        </form>
        
        <h2>Test Form 2 - Stored XSS (simulated)</h2>
        <form method="GET" action="/stored">
            <input type="text" name="comment" placeholder="Leave comment">
            <input type="submit" value="Post">
        </form>
        
        <h2>Test Form 3 - With WAF simulation</h2>
        <form method="GET" action="/waf">
            <input type="text" name="search" placeholder="Search...">
            <input type="submit" value="Search">
        </form>
    </body>
    </html>
    '''

@app.route('/reflected', methods=['POST'])
def reflected():
    user_input = request.form.get('input', '')
    # Intentionally vulnerable - no encoding
    return f'''
    <html>
    <body>
        <h2>You entered:</h2>
        <div>{user_input}</div>
        <a href="/">Back</a>
    </body>
    </html>
    '''

@app.route('/stored')
def stored():
    comment = request.args.get('comment', '')
    # Vulnerable if comment contains script
    return f'''
    <html>
    <body>
        <h2>Your comment:</h2>
        <div>{comment}</div>
        <h3>Previous comments:</h3>
        <div>Great site!</div>
        <div>Very useful</div>
        <a href="/">Back</a>
    </body>
    </html>
    '''

@app.route('/waf')
def waf():
    search = request.args.get('search', '')
    
    # Simulate basic WAF
    blocked_terms = ['script', 'alert', 'onerror', 'javascript']
    if any(term in search.lower() for term in blocked_terms):
        return '''
        <html>
        <body>
            <h2>Access Denied</h2>
            <p>Your request was blocked by security filter.</p>
            <a href="/">Back</a>
        </body>
        </html>
        ''', 403
    
    # Still vulnerable to encoded attacks
    return f'''
    <html>
    <body>
        <h2>Search results for: {search}</h2>
        <p>No results found.</p>
        <a href="/">Back</a>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print("=" * 50)
    print("NeuroXSS Test Application")
    print("=" * 50)
    print("Running on: http://localhost:5000")
    print("\nVulnerable endpoints:")
    print("- POST /reflected (unfiltered)")
    print("- GET /stored (unfiltered)")
    print("- GET /waf (basic filtering)")
    print("\nPress Ctrl+C to stop")
    print("=" * 50)
    app.run(debug=True, port=5000)