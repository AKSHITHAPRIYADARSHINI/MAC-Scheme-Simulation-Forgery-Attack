from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets
import string
import random

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

# ---- MAC Scheme Implementation ----
def F_k(key, message):
    """Custom pseudorandom function (NOT cryptographically secure)"""
    # Ensure key is at least as long as message
    if len(key) < len(message):
        key = (key * ((len(message) // len(key)) + 1))[:len(message)]

    # XOR characters and convert to a-z characters for output
    result = []
    for i in range(len(message)):
        k = ord(key[i])
        m = ord(message[i])
        combined = (k ^ m) % 26
        result.append(chr(ord('a') + combined))  # Map 0–25 to 'a'–'z'

    return ''.join(result)


def MAC(key, message):
    """Generate a MAC tag for the given message and key"""
    mid = len(message) // 2
    m0, m1 = message[:mid], message[mid:]
    t0 = F_k(key, '0' + m0)
    t1 = F_k(key, '1' + m1)
    return t0 + t1

def Vrfy(key, message, tag):
    """Verify if a tag is valid for the given message and key"""
    return MAC(key, message) == tag

# ---- MAC Oracle Implementation ----
class MACOracle:
    def __init__(self, key):
        self.key = key
        self.observed_pairs = []
    
    def get_tag(self, message):
        tag = MAC(self.key, message)
        self.observed_pairs.append((message, tag))
        return tag
    
    def verify(self, message, tag):
        return Vrfy(self.key, message, tag)
    
    def get_observed(self):
        return self.observed_pairs

# ---- Utilities ----
def generate_random_string(length=16):
    """Generate a random string of the specified length"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

# ---- Database Simulation ----
# Store active oracles by session ID
oracles = {}

# ---- Endpoints ----
@app.route('/generate-tag', methods=['POST'])
def generate_tag():
    data = request.json
    message = data.get('message', '')
    key = data.get('key', '')
    
    # Generate random values if not provided
    if not message:
        message = generate_random_string()
    if not key:
        key = generate_random_string()
    
    # Create a new oracle with this key
    session_id = generate_random_string(8)
    oracles[session_id] = MACOracle(key)
    
    # Generate the tag
    tag = oracles[session_id].get_tag(message)
    
    return jsonify({
        'message': message,
        'key': key,
        'tag': tag,
        'session_id': session_id
    })

@app.route('/verify-tag', methods=['POST'])
def verify_tag():
    data = request.json
    message = data.get('message', '')
    key = data.get('key', '')
    tag = data.get('tag', '')
    
    # Standard verification
    is_valid = Vrfy(key, message, tag)
    
    return jsonify({
        'is_valid': is_valid,
        'computed_tag': MAC(key, message)
    })

@app.route('/run-forgery', methods=['POST'])
def run_forgery():
    data = request.json
    session_id = data.get('session_id', '')
    
    if not session_id or session_id not in oracles:
        return jsonify({
            'error': 'Invalid session. Generate a tag first.'
        })
    
    # Use the attacker implementation with detailed steps
    oracle = oracles[session_id]
    forged_msg, forged_tag, success, attack_steps = attacker_using_oracle_with_steps(oracle)
    
    return jsonify({
        'forged_message': forged_msg,
        'forged_tag': forged_tag,
        'success': success,
        'attack_steps': attack_steps  # Return detailed attack steps
    })

# Updated attacker implementation that returns steps
def attacker_using_oracle_with_steps(oracle):
    # Query the oracle to observe valid tags
    oracle_queries = []
    for i in range(5):  # Reduced to 5 for clarity in the UI
        message = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=16))
        tag = oracle.get_tag(message)
        oracle_queries.append({
            'step': i+1,
            'message': message,
            'tag': tag
        })

    # Split observed messages and tags into halves
    halves_db = []
    for m, t in oracle.get_observed():
        mid = len(m) // 2
        m0, m1 = m[:mid], m[mid:]
        t0, t1 = t[:mid], t[mid:]
        halves_db.append((m0, m1, t0, t1))

    # Choose random halves to combine
    index1 = random.randint(0, len(halves_db) - 1)
    index2 = random.randint(0, len(halves_db) - 1)
    while index2 == index1:
        index2 = random.randint(0, len(halves_db) - 1)
        
    (m0a, _, t0a, _) = halves_db[index1]
    (_, m1b, _, t1b) = halves_db[index2]
    
    # Record the chosen messages for visualization
    chosen_messages = {
        'message1': oracle.get_observed()[index1][0],
        'tag1': oracle.get_observed()[index1][1],
        'message2': oracle.get_observed()[index2][0],
        'tag2': oracle.get_observed()[index2][1],
        'm0a': m0a,
        'm1b': m1b,
        't0a': t0a,
        't1b': t1b
    }

    # Create forged message and tag
    forged_msg = m0a + m1b
    forged_tag = t0a + t1b

    # Check if the forgery works
    success = oracle.verify(forged_msg, forged_tag)
    
    # Compile all steps for the UI
    attack_steps = {
        'oracle_queries': oracle_queries,
        'chosen_messages': chosen_messages,
        'forgery_explanation': {
            'description': 'The attack combines the first half of message 1 with the second half of message 2, and similarly combines their tags.',
            'forged_message': forged_msg,
            'forged_tag': forged_tag,
            'verification': success
        }
    }
    
    return forged_msg, forged_tag, success, attack_steps

# Attacker implementation (original version without steps)
def attacker_using_oracle(oracle):
    # Query the oracle to observe valid tags
    for _ in range(10):
        message = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=16))
        oracle.get_tag(message)

    halves_db = []
    for m, t in oracle.get_observed():
        mid = len(m) // 2
        m0, m1 = m[:mid], m[mid:]
        t0, t1 = t[:mid], t[mid:]
        halves_db.append((m0, m1, t0, t1))

    (m0a, _, t0a, _) = random.choice(halves_db)
    (_, m1b, _, t1b) = random.choice(halves_db)

    forged_msg = m0a + m1b
    forged_tag = t0a + t1b

    success = oracle.verify(forged_msg, forged_tag)
    return forged_msg, forged_tag, success

# Add a test route to verify the server is running
@app.route('/', methods=['GET'])
def test_route():
    return jsonify({"status": "MAC Server is running correctly"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)