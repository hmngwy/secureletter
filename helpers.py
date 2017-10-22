import json

import boto3
from botocore.exceptions import ClientError


def send_email(subject, msg, recipient):
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
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
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
