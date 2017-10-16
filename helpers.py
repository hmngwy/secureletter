import json


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
