import email
import json


def _get_ses_from_sns(event):
    return json.loads(event['Records'][0]['Sns']['Message'])


def _is_blocked(receipt):
    verdicts = {k: v['status'] for k, v in receipt.items(
    ) if k in ['spfVerdict', 'virusVerdict', 'dkimVerdict', 'spamVerdict']}
    if not all(verd == 'PASS' for verd in list(verdicts.values())):
        return True
    return False


def _get_signature(msg):
    for part in msg.walk():
        ctype = part.get_content_type()
        cdispo = str(part.get('Content-Disposition'))

        # If we find a signature, break
        if ctype == 'application/pgp-signature' and 'attachment' in cdispo:
            # Don't include headers in signature
            signature = part.get_payload()
            return signature

    return None


def _get_body(msg):
    for part in msg.walk():
        ctype = part.get_content_type()
        cdispo = str(part.get('Content-Disposition'))

        if ctype in ['text/plain', 'text/html'] and 'attachment' not in cdispo:
            return part  # Whole part is signed, incl headers

    return None


def unsubscribe(event, context):

    ses_message = _get_ses_from_sns(event)

    if _is_blocked(ses_message['receipt']):
        return "BLOCKED"

    msg = email.message_from_string(ses_message['content'])

    import boto3
    from boto3.dynamodb.conditions import Attr, Key
    from email.utils import parseaddr

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('subscribers')
    response = table.delete_item(
        Key={'pair': parseaddr(msg['From'])[
            1] + '-' + msg['Subject'].replace(' ', '')}
    )
    return 'UNSUBSCRIBE_SUCCESFUL'


def test(event, context):

    ses_message = _get_ses_from_sns(event)

    if _is_blocked(ses_message['receipt']):
        return "BLOCKED"

    import boto3
    from boto3.dynamodb.conditions import Attr, Key
    from email.utils import parseaddr

    msg = email.message_from_string(ses_message['content'])

    dynamodb = boto3.resource('dynamodb')

    # Newsletter exists
    table = dynamodb.Table('subscribers')
    response = table.query(
        IndexName='newsletter_key-index',
        KeyConditionExpression=Key('newsletter_key').eq(
            msg['Subject'].replace(' ', ''))
    )

    return response


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
    table = dynamodb.Table('newsletters')
    response = table.get_item(
        Key={'fingerprint': msg['Subject'].replace(' ', '')}
    )
    if 'Item' in response:
        # Newsletter exists
        table = dynamodb.Table('subscribers')
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
    signature = _get_signature(b)

    # Look for email body
    body = _get_body(b)

    if not signature:
        return 'NO_SIGNATURE_PART'

    if not body:
        return 'NO_BODY_PART'

    import gnupg
    import os

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
            tmp.write(str(signature))
            filename = tmp.name

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
        table = dynamodb.Table('newsletters')

        response = table.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(
                parseaddr(verified.username)[1])
        )

        if response['Count']:
            return 'ALREADY_REGISTERED'

        # TODO save plain email as index/key
        # Such that on publish, we verify signature with
        # fingerprint on file queried by email
        table.put_item(
            Item={
                'fingerprint': verified.fingerprint,
                'username': verified.username,
                'created_on': int(time.time()),
                'email': parseaddr(verified.username)[1]
            }
        )

        return 'SIGNATUREVALID_REGISTERED ',
