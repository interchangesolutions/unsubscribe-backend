# list_subscriptions.py
import requests
from googleapiclient.discovery import build
import datetime
import email.utils  # for parsing email headers
from googleapiclient.discovery import build

def get_subscriptions(creds, max_results=50):
    """
    Given a user's Credentials object, fetch subscription-like messages,
    process the headers to extract necessary info, and return a list of subscription data.
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

        # Parse "from" header to get name and email.
        parsed = email.utils.parseaddr(from_field)  # returns (name, email)
        name, email_address = parsed if parsed != ('', '') else ('Unknown', 'Unknown')

        # Parse "date" header for lastOpened (days since message date)
        date_str = header_dict.get('date')
        lastOpened = 0
        if date_str:
            try:
                msg_date = email.utils.parsedate_to_datetime(date_str)
                now = datetime.datetime.now(datetime.timezone.utc)
                lastOpened = (now - msg_date).days
            except Exception:
                lastOpened = 0

        # Set a default frequency (you may enhance this later)
        frequency = 0

        # Set a default category (could be enhanced with heuristics)
        category = "Other"

        subscription_data.append({
            'id': msg_id,               # Renamed key: 'id'
            'name': name,
            'email': email_address,
            'subject': subject,
            'unsubscribe': list_unsubscribe,
            'frequency': frequency,
            'lastOpened': lastOpened,
            'category': category,
        })

    return subscription_data

def unsubscribe_from_message(creds, msg_id):
    """
    Given a user's Credentials and a specific message_id,
    parse the List-Unsubscribe header and attempt to unsubscribe.
    Returns True if we successfully unsubscribed, False otherwise.
    """
    service = build('gmail', 'v1', credentials=creds)
    msg_details = service.users().messages().get(
        userId='me',
        id=msg_id,
        format='full'
    ).execute()

    headers = msg_details['payload'].get('headers', [])
    header_dict = {h['name'].lower(): h['value'] for h in headers}
    unsub_link = header_dict.get('list-unsubscribe', '').strip('<>')

    if unsub_link.startswith('http'):
        try:
            r = requests.get(unsub_link)
            print(f"Unsubscribe request for {msg_id} returned status {r.status_code}")  # Log the status
            return r.ok
        except Exception as e:
            print(f"Error unsubscribing from {msg_id}: {e}")
            return False
    elif unsub_link.startswith('mailto:'):
        return False

    return False
