"""Stop people from posting Wordle spoilers, unless they're in a thread."""
import os
import re

import flask
import slack_sdk
import slack_sdk.errors
import slack_sdk.signature


WORDLE_RE = re.compile(r'(:[a-z_]+_square:){5}', re.IGNORECASE)
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
SLACK_USER_TOKEN = os.environ.get('SLACK_USER_TOKEN')
SLACK_SIGNING_SECRET = os.environ.get('SLACK_SIGNING_SECRET')
SLACK_SIG_VERIFIER = slack_sdk.signature.SignatureVerifier(signing_secret=SLACK_SIGNING_SECRET)
SLACK_USER_CLIENT = slack_sdk.WebClient(token=SLACK_USER_TOKEN)
SLACK_BOT_CLIENT = slack_sdk.WebClient(token=SLACK_BOT_TOKEN)


def hello_world(request):
    """Responds to any HTTP request.
    Args:
        request (flask.Request): HTTP request object.
    Returns:
        The response text or any set of values that can be turned into a
        Response object using
        `make_response <http://flask.pocoo.org/docs/1.0/api/#flask.Flask.make_response>`.
    """
    if not SLACK_SIG_VERIFIER.is_valid(
            body=request.get_data(),
            timestamp=request.headers.get('X-Slack-Request-Timestamp'),
            signature=request.headers.get('X-Slack-Signature')):
        return flask.make_response('invalid request', 403)

    request_json = request.get_json()
    if not request_json:
        return 'Invalid invocation'

    event = request_json.get('event', {})
    message_text = event.get('text', '')
    is_message = event.get('type') == 'message'
    is_thread_reply = 'parent_user_id' in event
    is_spoiler = WORDLE_RE.search(message_text)
    is_debug = 'debug' in message_text
    if is_debug:
        print('Got (%r/%r/%r) %r request to %r: %r // %r // %r' % (
	    is_message, is_thread_reply, is_spoiler,
            request.method, request.url, request.headers, request.get_data(), message_text))

    if is_message and is_spoiler and not is_thread_reply:
        result = None
        result2 = None
        channel_id = event.get('channel')
        message_id = event.get('ts')
        user_id = event.get('user')

        try:
            result = SLACK_USER_CLIENT.chat_delete(channel=channel_id, ts=message_id, as_user=True)
        except slack_sdk.errors.SlackApiError as error:
            result = error

        try:
            result2 = SLACK_BOT_CLIENT.chat_postEphemeral(
                channel=channel_id,
                user=user_id,
                text=('It looks like you posted a Wordle result to the main channel! '
                      'Please post in a thread instead.'))
        except slack_sdk.errors.SlackApiError as error:
            result2 = error

        if is_debug:
            print('Top-level wordle alert! %r / %r / %r / %r' % (
                channel_id, message_id, result, result2))

    return request_json.get('challenge', '')
