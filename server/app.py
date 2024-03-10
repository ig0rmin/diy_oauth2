#!/usr/bin/env python
from flask import Flask
from pymongo import MongoClient

app = Flask(__name__)

# TODO: read from .env
client = MongoClient('mongodb', 27017)
db = client['statistics']
collection = db['counter']


@app.route("/")
def hello_world():
    return "<p>Server. Invocation count: {count}</p>".format(count = stat())

def stat():
    # Use $inc to atomically increment the counter
    result = collection.find_one_and_update({}, {'$inc': {'count': 1}}, upsert=True, return_document=True)

    return result['count']

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)