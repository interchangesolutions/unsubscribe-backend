# list_subscriptions.py
import requests
from googleapiclient.discovery import build

def get_subscriptions(creds, max_results=50):
    """
    Given a user's Credentials object (for the Gmail API), 
    fetch subscription-like messages (those containing 'unsubscribe').
    Return a list of subscription data.
    """
    service = build('gmail', 'v1', credentials=creds)

    query = 'unsubscribe'
    messages_list = service.users().messages().list(
        userId='me',
        q=query,
        maxResults=max_results
    ).execute()

    if 'messages' not in messages_list:
        return []

    subscription_data = []
    for msg in messages_list['messages']:
        msg_id = msg['id']
        # Get full email details
        msg_details = service.users().messages().get(
            userId='me',
            id=msg_id,
            format='full'
        ).execute()

        headers = msg_details['payload'].get('headers', [])
        header_dict = {h['name'].lower(): h['value'] for h in headers}

        from_field = header_dict.get('from', '')
        subject = header_dict.get('subject', '')
        list_unsubscribe = header_dict.get('list-unsubscribe', '')

        subscription_data.append({
            'message_id': msg_id,
            'from': from_field,
            'subject': subject,
            'unsubscribe': list_unsubscribe
        })

    return subscription_data

def unsubscribe_from_message(creds, msg_id):
    """
    Given a user's Credentials and a specific message_id,
    parse the List-Unsubscribe header and attempt to unsubscribe.
    Returns True if we successfully unsubscribed, False otherwise.
    """
    service = build('gmail', 'v1', credentials=creds)

    # Get message details
    msg_details = service.users().messages().get(
        userId='me',
        id=msg_id,
        format='full'
    ).execute()

    headers = msg_details['payload'].get('headers', [])
    header_dict = {h['name'].lower(): h['value'] for h in headers}

    unsub_link = header_dict.get('list-unsubscribe', '')
    # unsub_link might look like <http://example.com/unsub?token=abc> or <mailto:unsubscribe@example.com>
    unsub_link = unsub_link.strip('<>')

    # If it's an HTTP link, try GET (or POST) to unsubscribe
    if unsub_link.startswith('http'):
        try:
            r = requests.get(unsub_link)
            # Some unsubscribe links require POST or a special URL
            # Adjust as needed; this is just a naive GET.
            return r.ok
        except:
            return False
    elif unsub_link.startswith('mailto:'):
        # Optionally implement logic to send an unsubscribe email
        return False

    return False
