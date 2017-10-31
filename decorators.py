import email
import os

from helpers import _is_blocked
from helpers import _get_ses_from_sns
from helpers import _get_signature
from helpers import _get_body


def is_not_blocked(met):
    def wrapper(event, context, ses_message):

        if _is_blocked(ses_message['receipt']):
            return "BLOCKED"

        return met(event, context,
                   ses_message)
    return wrapper


def get_ses_message(ses_from='SNS'):
    def decorator(met):
        def wrapper(event, context):

            if ses_from == 'SNS':
                ses_message = _get_ses_from_sns(event)
            else:
                ses_message = event['Records'][0]['ses']

            return met(event, context,
                       ses_message=ses_message)

        return wrapper
    return decorator


def authenticate(content_from='inline', fingerprint_from='email_ref'):
    def decorator(met):
        def wrapper(event, context, ses_message):

            if content_from == 'inline':
                content = ses_message['content']
                b = email.message_from_string(content)
            else:
                import boto3
                import botocore
                from botocore.exceptions import ClientError
                bucket = 'secureletter-posts-' + \
                    os.environ.get('TARGET', 'develop')
                s3 = boto3.client('s3')
                try:
                    response = s3.get_object(
                        Bucket=bucket, Key=ses_message['mail']['messageId'])
                    content = response['Body'].read()
                    b = email.message_from_bytes(content)
                except ClientError as ex:
                    if ex.response['Error']['Code'] == 'NoSuchKey':
                        return 'BAD_KEY'
                    else:
                        raise ex

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

            if fingerprint_from == 'email_ref':
                import boto3
                from boto3.dynamodb.conditions import Key
                import time
                from email.utils import parseaddr

                dynamodb = boto3.resource('dynamodb')
                table = dynamodb.Table(os.environ.get(
                    'DDB_NEWSLETTERS_TABLE', 'newsletters-develop'))

                response = table.query(
                    IndexName='email-index',
                    KeyConditionExpression=Key('email').eq(
                        parseaddr(ses_message['mail']['source'])[1])
                )

                if not response['Count']:
                    return 'NOT_REGISTERED'
                else:
                    key = response['Items'][0]['fingerprint'].replace(' ', '')
            else:
                key = b['Subject'].strip().replace(' ', '')

            import gnupg
            from tempfile import TemporaryDirectory
            from tempfile import NamedTemporaryFile

            # Create an isolated GPG home, avoid cross-contamination
            with TemporaryDirectory() as tmpdir:
                print('created temporary directory', tmpdir)

                gpg = gnupg.GPG(gnupghome=tmpdir)
                import_res = gpg.recv_keys('keys.gnupg.net', key)

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

            return met(event, context,
                       verified=verified,
                       ses_message=ses_message,
                       mail=b)

        return wrapper
    return decorator
