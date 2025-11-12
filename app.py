from flask import Flask, request, jsonify
import collector

app = Flask(__name__)  # create Flask app

@app.route('/')
def home():
    return "AWS Collector API is running"

@app.route('/collect', methods=['GET'])
def run_collector():
    """Run the full data collector and return results"""
    results = collector.collect_all()  # call your collector_all function
    return jsonify(results)  # return JSON response

if __name__ == "__main__":
    app.run(debug=True)    
