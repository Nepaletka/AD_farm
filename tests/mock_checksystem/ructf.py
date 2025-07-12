from flask import Flask, request, jsonify
import random

app = Flask(__name__)

MOCK_RESPONSES = {
    'accepted': ['accepted', 'congratulations'],
    'rejected': ['wrong', 'expired', 'invalid flag', 'already submitted', 'your own flag'],
    'queued': ['timeout', 'game not started', 'try again later', 'game over', 'no such flag'],
}

def generate_mock_response(flag):
    verdict_type = random.choices(
        ['accepted', 'rejected', 'queued'],
        weights=[0.2, 0.6, 0.2],
        k=1
    )[0]
    message = random.choice(MOCK_RESPONSES[verdict_type])
    return {
        'flag': flag,
        'msg': f"[{flag}] {message}"
    }

@app.route('/flags', methods=['PUT'])
def receive_flags():
    try:
        flags = request.get_json(force=True)
        if not isinstance(flags, list):
            return jsonify({'error': 'Expected a list of flags'}), 400

        responses = [generate_mock_response(flag) for flag in flags]
        return jsonify(responses), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=31337)

