import email
import json
import os
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


def register(event, context):

    ses_message = _get_ses_from_sns(event)

    if _is_blocked(ses_message['receipt']):
        return "BLOCKED"

    b = email.message_from_string(ses_message['content'])

    if b.get_content_type() != 'multipart/signed':
        return 'UNSIGNED_EMAIL'

    if not b.is_multipart():
        return 'NONMULTIPART_EMAIL'

    # Look for signature
    signature, signature_payload = _get_signature(b)

    # Look for email body
    body, body_payload = _get_body(b)

    if not signature:
        return 'NO_SIGNATURE_PART'

    if not all(body):
        return 'NO_BODY_PART'

    import gnupg
    from tempfile import TemporaryDirectory
    from tempfile import NamedTemporaryFile

    key = b['Subject'].strip()

    # Create an isolated GPG home, avoid cross-contamination
    with TemporaryDirectory() as tmpdir:
        print('created temporary directory', tmpdir)

        gpg = gnupg.GPG(gnupghome=tmpdir)
        import_res = gpg.recv_keys('keyserver.ubuntu.com', key)

        if not import_res.fingerprints:
            return 'KEY_NOT_FOUND ' + key

        with NamedTemporaryFile(delete=False, mode='w') as tmp:
            tmp.write(signature_payload.decode('utf-8'))
            filename = tmp.name

        # The whole ascii body "part" is signed
        verified = gpg.verify_data(filename, bytes(body))
        os.remove(filename)

        if not verified:
            return "DONOTTRUST"

        if verified.key_status:
            return "REVOKED_OR_EXPIRED_KEY"

        # At this point we know that body is signed by user

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


def publish(event, context):

    ses_message = event['Records'][0]['ses']

    if _is_blocked(ses_message['receipt']):
        return "BLOCKED"

    import boto3
    import botocore
    bucket = 'secureletter-posts-' + os.environ.get('TARGET', 'develop')
    s3 = boto3.client('s3')
    response = s3.get_object(
        Bucket=bucket, Key=ses_message['mail']['messageId'])

    # Read the raw text file into a Email Object
    b = email.message_from_bytes(response['Body'].read())

    if b.get_content_type() != 'multipart/signed':
        return 'UNSIGNED_EMAIL'

    if not b.is_multipart():
        return 'NONMULTIPART_EMAIL'

    # Look for signature
    signature, signature_payload = _get_signature(b)

    # Look for email body
    body, body_payload = _get_body(b)

    if not signature:
        return 'NO_SIGNATURE_PART'

    if not body:
        return 'NO_BODY_PART'

    # HERE THE EMAIL IS VALID

    import boto3
    from boto3.dynamodb.conditions import Key
    import time
    from email.utils import parseaddr

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['DDB_NEWSLETTERS_TABLE'])

    response = table.query(
        IndexName='email-index',
        KeyConditionExpression=Key('email').eq(
            parseaddr(ses_message['mail']['source'])[1])
    )

    if not response['Count']:
        return 'NOT_REGISTERED'
    else:
        key = response['Items'][0]['fingerprint']

    import gnupg
    from tempfile import TemporaryDirectory
    from tempfile import NamedTemporaryFile

    # Create an isolated GPG home, avoid cross-contamination
    with TemporaryDirectory() as tmpdir:
        print('created temporary directory', tmpdir)

        gpg = gnupg.GPG(gnupghome=tmpdir)
        import_res = gpg.recv_keys('keyserver.ubuntu.com', key)

        if not import_res.fingerprints:
            return 'KEY_NOT_FOUND ' + key

        with NamedTemporaryFile(delete=False, mode='w') as tmp:
            tmp.write(signature_payload.decode('utf-8'))
            filename = tmp.name

        # The whole ascii body "part" is signed
        verified = gpg.verify_data(filename, bytes(body))
        os.remove(filename)

        if not verified:
            return "DONOTTRUST"

        if verified.key_status:
            return "REVOKED_OR_EXPIRED_KEY"

        # At this point we know that body is signed by user

        return 'QUEUE_EMAILS'
