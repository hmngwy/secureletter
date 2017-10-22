import email
import json
import os
import time
from email.utils import parseaddr

import boto3
from boto3.dynamodb.conditions import Attr, Key

from decorators import authenticate
from decorators import get_ses_message
from decorators import is_not_blocked


import helpers


@get_ses_message(ses_from='SNS')
@is_not_blocked
def unsubscribe(event, context, ses_message):

    msg = email.message_from_string(ses_message['content'])

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ.get(
        'DDB_SUBSCRIBERS_TABLE', 'subscribers-develop'))
    table.delete_item(
        Key={'pair': parseaddr(msg['From'])[
            1] + '-' + msg['Subject'].replace(' ', '')}
    )
    return 'UNSUBSCRIBE_SUCCESFUL'


@get_ses_message(ses_from='SNS')
@is_not_blocked
def subscribe(event, context, ses_message):

    msg = email.message_from_string(ses_message['content'])

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ.get(
        'DDB_NEWSLETTERS_TABLE', 'newsletters-develop'))
    response = table.get_item(
        Key={'fingerprint': msg['Subject'].replace(' ', '')}
    )
    if 'Item' in response:
        # Newsletter exists
        table = dynamodb.Table(os.environ.get(
            'DDB_SUBSCRIBERS_TABLE', 'subscribers-develop'))
        response = table.get_item(
            Key={'pair': parseaddr(msg['From'])[
                1] + '-' + msg['Subject'].replace(' ', '')}
        )
        if 'Item' not in response:
            table.put_item(
                Item={
                    'pair': parseaddr(msg['From'])[1] + '-' + msg['Subject'].replace(' ', ''),
                    'email': parseaddr(msg['From'])[1],
                    'newsletter_key': msg['Subject'].replace(' ', '')
                }
            )
            return 'SUBSCRIBE_SUCCESFUL'
        else:
            return 'ALREADY_SUBSCRIBED'
    else:
        return 'NEWSLETTER_DNE'

    return msg['Subject'].replace(' ', '')


@get_ses_message(ses_from='SNS')
@is_not_blocked
@authenticate(fingerprint_from='subject')
def register(event, context, *args, **kwargs):

    verified = kwargs.get('verified')
    ses_message = kwargs.get('ses_message')
    mail = kwargs.get('mail')

    sender = parseaddr(verified.username)[1]

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ.get(
        'DDB_NEWSLETTERS_TABLE', 'newsletters-develop'))

    response = table.query(
        IndexName='email-index',
        KeyConditionExpression=Key('email').eq(sender)
    )

    if response['Count']:
        return 'ALREADY_REGISTERED'

    table.put_item(
        Item={
            'fingerprint': verified.fingerprint,
            'username': verified.username,
            'created_on': int(time.time()),
            'email': sender
        }
    )

    helpers.send_email(
        'SecureLetter Registration Successful',
        'People can subscribe to your Newsletter by sending an ' +
        'email to subscribe@ with your full GPG Public Key Fingerprint ' +
        'in the email subject. \n\n ' +
        'You are registered as ' + verified.fingerprint,
        sender)

    return 'SIGNATUREVALID_REGISTERED '


@get_ses_message(ses_from='SES')
@is_not_blocked
@authenticate(content_from='s3')
def publish(event, context, *args, **kwargs):
    verified = kwargs.get('verified')
    ses_message = kwargs.get('ses_message')
    mail = kwargs.get('mail')

    return 'QUEUE_EMAILS'
