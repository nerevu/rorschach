from os import environ, urandom
from functools import partial

from flask import Flask, request, redirect, session, url_for
from flask.json import jsonify
from requests_oauthlib import OAuth2Session
from riko.dotdict import DotDict
from meza import process as pr

app = Flask(__name__)


# This information is obtained upon registration of a new Timely OAuth
# application here: https://app.timelyapp.com/777870/oauth_applications
CLIENT_ID = environ.get("TIMELY_CLIENT_ID")
CLIENT_SECRET = environ.get("TIMELY_SECRET")
API_BASE_URL = "https://api.timelyapp.com/1.1"
AUTHORIZATION_BASE = "oauth/authorize"
TOKEN_BASE = "oauth/token"
TIMELY_ACCOUNT_ID = "777870"
REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}
LOCALHOST = True

authorization_base_url = f"{API_BASE_URL}/{AUTHORIZATION_BASE}"
token_url = f"{API_BASE_URL}/{TOKEN_BASE}"

TIMELY_XERO_ID_MAPPINGS = {}

# http://flask.pocoo.org/docs/1.0/appcontext/#storing-data

@app.route("/")
def demo():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    timely = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI)
    authorization_url, state = timely.authorization_url(authorization_base_url)

    # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)


# Step 2: User authorization, this happens on the provider.

@app.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    if session.get("oauth_state"):
        timely = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, state=session['oauth_state'])
        token_func = partial(timely.fetch_token, token_url, client_secret=CLIENT_SECRET)

        if request.args.get("code"):
            token = token_func(code=request.args["code"])
        else:
            token = token_func(authorization_response=request.url)

        # At this point you can fetch protected resources
        session['oauth_token'] = token
        return redirect(url_for('.data'))
    else:
        return redirect(url_for('.demo'))


def extract_fields(record, fields):
    item = DotDict(record)

    for field in fields:
        if '[' in field:
            split_field = field.split('[')
            real_field = split_field[0]
            pos = int(split_field[1].split(']')[0])
            value = item[real_field][pos]
        else:
            value = item[field]

        yield (field, value)


def gen_unbilled(events, fields):
    for event in events:
        if not (event['billed'] or event['deleted']):
            yield dict(extract_fields(event, fields))


@app.route("/data", methods=["GET"])
def data():
    """Fetching a protected resource using an OAuth 2 token.
    """
    if session.get("oauth_token"):
        base_url = f"{API_BASE_URL}/{TIMELY_ACCOUNT_ID}/events"
        timely = OAuth2Session(CLIENT_ID, token=session['oauth_token'])
        response = timely.get(base_url, headers=HEADERS, params={"since": "2019-09-01", "upto": "2019-10-01"})
        events = response.json()
        fields = ['id', 'day', 'duration.total_minutes', 'label_ids[0]', 'project.id', 'user.id']
        json = list(gen_unbilled(events, fields))
    else:
        json = "no oauth_token"

    return jsonify(json)


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = urandom(24)
    app.run(debug=True)


