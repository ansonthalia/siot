
import datetime

import os
import flask
import requests

import google.oauth2.credentials
import google_auth_oauthlib.flow

import googleapiclient.discovery
import fitbit

# specify the fitbit OAuth2 credentials and scope

FITBIT_SECRET = "client_secret.json"
FITBIT_SCOPE = ['sleep']

# specify the API Key base URL and key for Google Maps

GEOLOCATION_BASE_URL = ["https://www.googleapis.com"]

flask_key = os.urandom(16)

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = flask_key

@app.route('/')
def index():
  return print_index_table()


@app.route('/test')
def test_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  authd_client = fitbit.Fitbit(
      credentials.client_id, credentials.client_secret,
      access_token=credentials.token, refresh_token=credentials.refresh_token)

  date = datetime.date.today()
  files = authd_client.get_sleep(date)

  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  flask.session['credentials'] = credentials_to_dict(credentials)

  return (flask.jsonify(**files))


@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      FITBIT_SECRET, scopes=FITBIT_SCOPE)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      FITBIT_SECRET, scopes=FITBIT_SCOPE, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.redirect(flask.url_for('test_api_request'))


@app.route('/collect')
def collect():

    # user dependent parameters
    # see https://developers.google.com/maps/documentation/

    params = {}
    params["homeMobileCountryCode"] =
    params["homeMobileNetworkCode"] =
    params["radioType"] = ''
    params["carrier"] = ''
    params["considerIp"] = "true"
    params["cellTowers"] = [
    ]

    params["wifiAccessPoints"] = {
    }

    location = request("/geolocation/v1/geolocate", {},
                base_url=_GEOLOCATION_BASE_URL,
                extract_body=_geolocation_extract,
                post_json=params)

    date = datetime.date.today()
    sleep = authd_client.get_sleep(date)

    entity = datastore.Entity(key=datastore_client.key('visit'))
    entity.update({
        'timestamp': date,
        'location': location,
        'sleep': sleep
    })

    datastore_client.put(entity)

    return flask.redirect(flask.url_for('datastore'))


@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return ('Credentials have been cleared.<br><br>' +
          print_index_table())

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def print_index_table():
  return ('<table>' +
          '<tr><td><a href="/test">Authorization Test</a></td>' +
          '<td>Test whether the webapp to access your Fitbit data. ' +
          '    Go through the authorization flow if there are no stored ' +
          '    credentials for the user.</td></tr>' +
          '<tr><td><a href="/collect">Begin Collection</a></td>' +
          '<td>Start an auotmated collection of Fitbit sleep data at daily intervals. ' +
          '    This will also initiate the collection of Geolocation data.' +
          '    Data will be stored in the Google Cloud Platform Datastore.' +
          '</td></tr>' +
          '<tr><td><a href="/clear">Clear Credentials</a></td>' +
          '<td>Clear the access token currently stored in the user session. ' +
          '    After clearing the token, if you <a href="/test">test the ' +
          '    API request</a> again, you should go back to the auth flow.' +
          '</td></tr></table>')

@app.route('/datastore')
def datastore():
    time = datetime.datetime.now()
    strtime = str(time)

    return ('Data collection began on: ' + strtime)

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run('localhost', 8080, debug=True)
