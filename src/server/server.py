from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

app = Flask(__name__)

DATABASE = {
    "bundle": None,
    "init_mes": None
}

@app.route('/publish_bundle', methods=['POST'])
def publish_keys():
    """Endpoint for a user to publish their keys."""
    data = request.json
    DATABASE['bundle'] = data
    return jsonify({"message": "Keys published successfully!"})

@app.route('/get_bundle', methods=['GET'])
def get_prekey_bundle():
    """Endpoint for a sender to fetch a recipient's prekey bundle."""
    if not DATABASE['bundle']:
        return jsonify({"error": "Bundle not found"}), 404

    return jsonify(DATABASE['bundle'])

@app.route('/send_init_message', methods=['POST'])
def send_message():
    """Endpoint for a user to send a message to another user."""
    data = request.json
    DATABASE['init_mes'] = data
    
    return jsonify({"message": "Message sent successfully!"})

@app.route('/get_init_message', methods=['GET'])
def get_messages():
    """Endpoint for a user to retrieve their messages."""
    if not DATABASE['init_mes']:
        return jsonify({"error": "Initial message not found"}), 404
    
    return jsonify(DATABASE['init_mes'])

if __name__ == '__main__':
    app.run(debug=True)
