import os
import base64
import json
import re
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from openai import OpenAI
from email.mime.text import MIMEText

# Load environment variables from .env
load_dotenv()

# Define Gmail API Scopes
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose"
]

# Initialize OpenAI client securely
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def authenticate_gmail():
    """Authenticate Gmail API using environment variables."""
    creds = None

    # Load credentials from token.json if it exists
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    # If credentials are missing or expired, refresh them or generate new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            creds = Credentials(
                token=os.getenv("GMAIL_ACCESS_TOKEN"),
                refresh_token=os.getenv("GMAIL_REFRESH_TOKEN"),
                client_id=os.getenv("GMAIL_CLIENT_ID"),
                client_secret=os.getenv("GMAIL_CLIENT_SECRET"),
                token_uri=os.getenv("GMAIL_TOKEN_URI"),
            )
        
        # Save new credentials to token.json
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return creds


def generate_reply(email_content):
    try:
        # Define the conversation structure
        messages = [
            {"role": "system", "content": "You are an AI email assistant. Respond professionally and politely without using placeholder brackets."},
            {"role": "user", "content": f"Email:\n{email_content}\n\nGenerate a reply:"}
        ]

        # Call OpenAI API
        print("Sending request to OpenAI API...")
        completion = client.chat.completions.create(
            model="gpt-4o-mini",  
            store=True,
            messages=messages
        )
        print("Response received from OpenAI:", completion)

        # Extract response and clean text
        response_text = completion.choices[0].message.content.strip()
        response_text = re.sub(r"\[.*?\]", "", response_text)

        return response_text
    except Exception as e:
        print(f"Error generating reply: {e}")
        return "Sorry, I couldn't generate a response due to an error."

def extract_email_details(msg_data):
    headers = msg_data['payload']['headers']
    email_from = next(header['value'] for header in headers if header['name'] == 'From')
    email_subject = next(header['value'] for header in headers if header['name'] == 'Subject')
    email_body = msg_data['snippet']
    thread_id = msg_data.get('threadId', None)
    return email_from, email_subject, email_body, thread_id

def create_draft(creds, to_email, subject, body_text, thread_id):
    service = build('gmail', 'v1', credentials=creds)
    message = MIMEText(body_text)
    message['to'] = to_email
    message['subject'] = subject
    message['In-Reply-To'] = thread_id
    message['References'] = thread_id
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    draft = {
        'message': {
            'raw': raw,
            'threadId': thread_id
        }
    }
    try:
        created_draft = service.users().drafts().create(userId="me", body=draft).execute()
        print(f"Draft created for {to_email} in thread {thread_id}: {created_draft['id']}")
    except Exception as e:
        print(f"An error occurred while creating draft: {e}")

def load_processed_emails():
    if os.path.exists('processed_emails.json'):
        with open('processed_emails.json', 'r') as file:
            return json.load(file)
    return []

def save_processed_emails(email_ids):
    with open('processed_emails.json', 'w') as file:
        json.dump(email_ids, file)

def auto_reply_to_last_two_unread_emails(creds):
    service = build('gmail', 'v1', credentials=creds)
    processed_emails = load_processed_emails()
    try:
        # Get unread emails
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q='is:unread').execute()
        messages = results.get('messages', [])

        new_emails = []
        for msg in messages:
            if msg['id'] not in processed_emails:
                new_emails.append(msg)
            if len(new_emails) == 2:
                break

        for msg in new_emails:
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            email_from, email_subject, email_body, thread_id = extract_email_details(msg_data)

            # Generate AI reply
            print(f"Generating reply for email from {email_from}...")
            reply_content = generate_reply(email_body)
            print(f"Reply generated:\n{reply_content}")

            # Create draft in the same thread
            create_draft(creds, email_from, f"Re: {email_subject}", reply_content, thread_id)

            # Mark email as processed
            processed_emails.append(msg['id'])

        save_processed_emails(processed_emails)

    except Exception as e:
        print(f"An error occurred while auto-replying: {e}")

# Authenticate and process unread emails
creds = authenticate_gmail()
auto_reply_to_last_two_unread_emails(creds)
