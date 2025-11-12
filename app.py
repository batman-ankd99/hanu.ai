from flask import Flask, request, jsonify
import collector

app = Flask(__name__)  # create Flask app
