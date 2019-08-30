import os

from flask import Flask
from flask import request

from fedservice.metadata_api.fs import make_entity_statement


basedir = os.path.abspath(os.path.dirname(__file__))

ROOT_DIR = os.path.join(basedir, "base_data")

app = Flask(__name__)


@app.route('/')
def index():
    if 'operation' in request.args:
        if request.args['operation'] == "fetch":
            return fetch()
    else:  # default is 'fetch'
        return fetch()


# --- MDSS operations ----

def fetch():
    iss = request.args['iss']  # required
    if 'sub' in request.args:
        statement = make_entity_statement(iss, ROOT_DIR, request.args['sub'])
    else:
        statement = make_entity_statement(iss, ROOT_DIR)
    return statement


if __name__ == '__main__':
    app.run()
