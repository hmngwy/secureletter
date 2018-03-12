"""Helper methods."""
import json

from email.utils import parseaddr

from messages import M

import boto3
from botocore.exceptions import ClientError


def get_ddb_table(table):
    """Return dynamodb table."""
    ddb = boto3.resource('dynamodb')
    return ddb.Table(table)


def get_fingerprint_from_subject(message):
    """Return Fingerprint from email subject."""
    return message['Subject'].replace(' ', '')


def get_sender_address(message):
    """Return sender address from email."""
    return parseaddr(message['From'])[1]


def get_address_from_gpg_username(username):
    """Return email from gpg username."""
    return parseaddr(username)[1]


def create_new_email(msg):
    """Return new email from existing."""
    parts = []
    for part in msg.walk():
        # multipart/* are just containers
        if part.get_content_maintype() == 'multipart':
            continue
        parts.append(part)

    from email.mime.multipart import MIMEMultipart
    new_msg = MIMEMultipart('alternative')
    for part in parts:
        new_msg.attach(part)

    return new_msg


def send_letter(recipient, subject, body):
    client = boto3.client('ses', region_name='us-west-2')
    # Try to send the email.
    try:
        # Provide the contents of the email.
        response = client.send_raw_email(
            Source='noreply@manilafunctional.com',
            Destinations=[
                recipient
            ],
            RawMessage={
                'Data': bytes(body)
            }
        )
    # Display an error if something goes wrong.
    except ClientError as error:
        print(error.response['Error']['Message'])
    else:
        print("Email sent! Message ID:")
        print(response['ResponseMetadata']['RequestId'])


def send_message(tag, recipient, subject_vars=None, body_vars=None):
    """Send a string-format-templated email."""
    _send_email(M.get(tag)['subject'].format(**subject_vars),
                M.get(tag)['body'].format(**body_vars),
                recipient)


def _send_email(subject, msg, recipient):
    client = boto3.client('ses', region_name='us-west-2')
    # Try to send the email.
    try:
        # Provide the contents of the email.
        response = client.send_email(
            Destination={
                'ToAddresses': [
                    recipient,
                ],
            },
            Message={
                'Body': {
                    'Text': {
                        'Charset': 'UTF-8',
                        'Data': msg,
                    },
                },
                'Subject': {
                    'Charset': 'UTF-8',
                    'Data': subject,
                },
            },
            Source='noreply@manilafunctional.com'
        )
    # Display an error if something goes wrong.
    except ClientError as error:
        print(error.response['Error']['Message'])
    else:
        print("Email sent! Message ID:")
        print(response['ResponseMetadata']['RequestId'])


def _get_body(msg):
    for part in msg.walk():
        ctype = part.get_content_type()
        cdispo = str(part.get('Content-Disposition'))

        if ctype in ['text/plain', 'text/html'] and 'attachment' not in cdispo:
            # Whole part is signed, incl headers
            return part, part.get_payload(decode=True)

    return None, None


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
            signature = part.get_payload(decode=True)
            return part, signature

    return None, None
