import email
import json
import os
from authenticate import authenticate
from helpers import _is_blocked
from helpers import _get_ses_from_sns
from helpers import _get_signature
from helpers import _get_body


def unsubscribe(event, context):

    ses_message = _get_ses_from_sns(event)

    if _is_blocked(ses_message['receipt']):
        return "BLOCKED"

    msg = email.message_from_string(ses_message['content'])

    import boto3
    from boto3.dynamodb.conditions import Attr, Key
    from email.utils import parseaddr

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['DDB_SUBSCRIBERS_TABLE'])
    table.delete_item(
        Key={'pair': parseaddr(msg['From'])[
            1] + '-' + msg['Subject'].replace(' ', '')}
    )
    return 'UNSUBSCRIBE_SUCCESFUL'


def subscribe(event, context):

    ses_message = _get_ses_from_sns(event)

    if _is_blocked(ses_message['receipt']):
        return "BLOCKED"

    import boto3
    from email.utils import parseaddr
    from boto3.dynamodb.conditions import Key
    from boto3.dynamodb.conditions import Attr

    msg = email.message_from_string(ses_message['content'])

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['DDB_NEWSLETTERS_TABLE'])
    response = table.get_item(
        Key={'fingerprint': msg['Subject'].replace(' ', '')}
    )
    if 'Item' in response:
        # Newsletter exists
        table = dynamodb.Table(os.environ['DDB_SUBSCRIBERS_TABLE'])
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


@authenticate(fingerprint_from='subject', ses_from='SNS')
def register(event, context, *args, **kwargs):
    verified = kwargs.get('verified')
    ses_message = kwargs.get('ses_message')
    mail = kwargs.get('mail')

    import boto3
    from boto3.dynamodb.conditions import Key
    import time
    from email.utils import parseaddr

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['DDB_NEWSLETTERS_TABLE'])

    response = table.query(
        IndexName='email-index',
        KeyConditionExpression=Key('email').eq(
            parseaddr(verified.username)[1])
    )

    if response['Count']:
        return 'ALREADY_REGISTERED'

    table.put_item(
        Item={
            'fingerprint': verified.fingerprint,
            'username': verified.username,
            'created_on': int(time.time()),
            'email': parseaddr(verified.username)[1]
        }
    )

    return 'SIGNATUREVALID_REGISTERED '


@authenticate(content_from='s3', ses_from='SES')
def publish(event, context, *args, **kwargs):
    verified = kwargs.get('verified')
    ses_message = kwargs.get('ses_message')
    mail = kwargs.get('mail')

    return 'QUEUE_EMAILS'
