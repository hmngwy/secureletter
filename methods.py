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
from helpers import send_message


@get_ses_message(ses_from='SNS')
@is_not_blocked
def unsubscribe(event, context, ses_message):

    msg = email.message_from_string(ses_message['content'])
    sender = parseaddr(msg['From'])[1]
    newsletter_fp = msg['Subject'].replace(' ', '')

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ.get(
        'DDB_SUBSCRIBERS_TABLE', 'subscribers-develop'))
    table.delete_item(
        Key={'pair': sender + '-' + newsletter_fp}
    )
    send_message('unsubscribe_successful', sender,
                 subject_vars={'fingerprint': newsletter_fp})  # ←
    return 'UNSUBSCRIBE_SUCCESFUL'


@get_ses_message(ses_from='SNS')
@is_not_blocked
def subscribe(event, context, ses_message):

    msg = email.message_from_string(ses_message['content'])
    sender = parseaddr(msg['From'])[1]
    newsletter_fp = msg['Subject'].replace(' ', '')

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ.get(
        'DDB_NEWSLETTERS_TABLE', 'newsletters-develop'))
    response = table.get_item(
        Key={'fingerprint': newsletter_fp}
    )
    if 'Item' in response:
        # Newsletter exists
        table = dynamodb.Table(os.environ.get(
            'DDB_SUBSCRIBERS_TABLE', 'subscribers-develop'))
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
@authenticate(content_from='s3')
def publish(event, context, *args, **kwargs):
    verified = kwargs.get('verified')
    ses_message = kwargs.get('ses_message')
    mail = kwargs.get('mail')

    return 'QUEUE_EMAILS'
