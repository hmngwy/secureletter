"""AWS Lambda handlers."""
import email
import os
import time

from fleece.xray import (monkey_patch_botocore_for_xray)

from decorators import authenticate
from decorators import get_ses_message
from decorators import is_not_blocked

from helpers import send_letter
from helpers import send_message
from helpers import get_sender_address
from helpers import get_address_from_gpg_username
from helpers import get_fingerprint_from_subject
from helpers import get_ddb_table

monkey_patch_botocore_for_xray()
TARGET = os.environ.get('TARGET', 'develop')


@get_ses_message(ses_from='SNS')
@is_not_blocked
def unsubscribe(event, context, ses_message):  # pylint: disable=W0613
    """Unsubscribe a user from a newsletter."""
    msg = email.message_from_string(ses_message['content'])
    sender = get_sender_address(msg)
    newsletter_fp = get_fingerprint_from_subject(msg)

    table = get_ddb_table('secureletter-subscribers-' + TARGET)
    table.delete_item(Key={'pair': sender + '-' + newsletter_fp})
    send_message('unsubscribe_successful', sender,
                 subject_vars={'fingerprint': newsletter_fp})  # ←

    return 'UNSUBSCRIBE_SUCCESFUL'


@get_ses_message(ses_from='SNS')
@is_not_blocked
def subscribe(event, context, ses_message):  # pylint: disable=W0613
    """Subscribe a user to a newsletter."""
    msg = email.message_from_string(ses_message['content'])
    sender = get_sender_address(msg)
    newsletter_fp = msg['Subject'].replace(' ', '')

    table = get_ddb_table('secureletter-newsletters-' + TARGET)
    response = table.get_item(Key={'fingerprint': newsletter_fp})

    if 'Item' in response:
        # Newsletter exists
        table = get_ddb_table('secureletter-subscribers-' + TARGET)
        response = table.get_item(
            Key={'pair': sender + '-' + msg['Subject'].replace(' ', '')}
        )
        if 'Item' in response:
            send_message('already_subscribed', sender,
                         subject_vars={'fingerprint': newsletter_fp})  # ←
            return 'ALREADY_SUBSCRIBED'

        table.put_item(
            Item={
                'pair': sender + '-' + newsletter_fp,
                'email': sender,
                'newsletter_key': newsletter_fp
            }
        )
        send_message('subscribe_successful', sender,
                     subject_vars={'fingerprint': newsletter_fp})  # ←

        return 'SUBSCRIBE_SUCCESFUL'

    else:
        send_message('newsletter_dne', sender,
                     body_vars={'fingerprint': newsletter_fp})  # ←
        return 'NEWSLETTER_DNE'

    return msg['Subject'].replace(' ', '')


@get_ses_message(ses_from='SNS')
@is_not_blocked
@authenticate(content_from='inline', fingerprint_from='subject')
def register(event, context, *args, **kwargs):  # pylint: disable=W0613
    """Register user."""
    from boto3.dynamodb.conditions import Key

    verified = kwargs.get('verified')
    # ses_message = kwargs.get('ses_message')
    # mail = kwargs.get('mail')

    sender = get_address_from_gpg_username(verified.username)

    table = get_ddb_table('secureletter-newsletters-' + TARGET)

    response = table.query(
        IndexName='email-index',
        KeyConditionExpression=Key('email').eq(sender)
    )

    if response['Count']:
        send_message('already_registered', sender)  # ←
        return 'ALREADY_REGISTERED'

    table.put_item(
        Item={
            'fingerprint': verified.fingerprint,
            'username': verified.username,
            'created_on': int(time.time()),
            'email': sender
        }
    )

    send_message('register_success', sender,
                 body_vars={'fingerprint': verified.fingerprint})  # ←

    return 'SIGNATUREVALID_REGISTERED'


@get_ses_message(ses_from='SES')
@is_not_blocked
@authenticate(content_from='s3', fingerprint_from='email_ref')
def publish(event, context, *args, **kwargs):  # pylint: disable=W0613
    """Send out an email by a registered user."""
    from boto3.dynamodb.conditions import Attr
    verified = kwargs.get('verified')

    # get list of subscribers
    # for each subscriber queue verified email body

    table = get_ddb_table('secureletter-subscribers-' + TARGET)
    response = table.scan(
        FilterExpression=Attr('newsletter_key').eq(verified.fingerprint)
    )

    if response['Count']:
        for item in response['Items']:
            send_letter(item['email'], 'TEST', kwargs.get('mail'))

    return 'QUEUE_EMAILS'
