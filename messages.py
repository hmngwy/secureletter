"""Holds format friendly email strings."""

M = {
    'register_success': {
        'subject': 'SecureLetter: Registration Successful',
        'body': 'People can subscribe to your Newsletter by sending an ' +
                'email to subscribe@ with your full GPG Public Key ' +
                'Fingerprint in the email subject.\n\n' +
                'You are registered as {fingerprint}.'
    },

    'already_registered': {
        'subject': 'SecureLetter: This email is already registered',
        'body': '✔'
    },

    'subscribe_successful': {
        'subject': 'SecureLetter: You subscribed to {fingerprint}',
        'body': '✔'
    },

    'already_subscribed': {
        'subject': 'SecureLetter: You are already subscribed to {fingerprint}',
        'body': '✔'
    },

    'newsletter_dne': {
        'subject': 'SecureLetter: This newsletter does not exist',
        'body': 'Double check the fingerprint: {fingerprint}'
    },

    'unsubscribe_successful': {
        'subject': 'SecureLetter: You unsubscribed from {fingerprint}',
        'body': '✔'
    }

}
