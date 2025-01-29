from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import os.path
from openai import OpenAI
import base64
from email.mime.text import MIMEText
import json
import re

# Define the scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.compose']

# Initialize the OpenAI client with the project-specific API key
client = OpenAI(
    api_key="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"
)

def authenticate_gmail():
    creds = None
    # Check if token.json exists
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=8080)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def generate_reply(email_content):
    try:
        # Define the conversation structure
        messages = [
            {"role": "system", "content": "You are an AI email assistant. Respond professionally and politely without using placeholder brackets."},
            {"role": "user", "content": f"Email:\n{email_content}\n\nGenerate a reply:"}
        ]

        # Call the OpenAI client with the correct method
        print("Sending request to OpenAI API...")
        completion = client.chat.completions.create(
            model="gpt-4o-mini",  # Use the appropriate model
            store=True,
            messages=messages
        )
        print("Response received from OpenAI:", completion)

        # Extract response and remove any placeholder brackets
        response_text = completion.choices[0].message.content.strip()
        response_text = re.sub(r"\[.*?\]", "", response_text)  # Remove text within square brackets

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
    message['In-Reply-To'] = thread_id  # Ensure it replies within the thread
    message['References'] = thread_id
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    draft = {
        'message': {
            'raw': raw,
            'threadId': thread_id  # Ensure draft is in the same thread
        }
    }
    try:
        created_draft = service.users().drafts().create(userId="me", body=draft).execute()
        print(f"Draft created for {to_email} in thread {thread_id}: {created_draft['id']}")
    except Exception as e:
        print(f"An error occurred while creating draft: {e}")

def load_processed_emails():
    # Load the list of processed email IDs from a file
    if os.path.exists('processed_emails.json'):
        with open('processed_emails.json', 'r') as file:
            return json.load(file)
    return []

def save_processed_emails(email_ids):
    # Save the list of processed email IDs to a file
    with open('processed_emails.json', 'w') as file:
        json.dump(email_ids, file)

def auto_reply_to_last_two_unread_emails(creds):
    service = build('gmail', 'v1', credentials=creds)
    processed_emails = load_processed_emails()
    try:
        # Get unread messages in the inbox
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q='is:unread').execute()
        messages = results.get('messages', [])

        new_emails = []
        for msg in messages:
            if msg['id'] not in processed_emails:
                new_emails.append(msg)
            if len(new_emails) == 2:  # Limit to the last two unread emails
                break

        for msg in new_emails:
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            email_from, email_subject, email_body, thread_id = extract_email_details(msg_data)

            # Generate AI reply
            print(f"Generating reply for email from {email_from}...")
            reply_content = generate_reply(email_body)
            print(f"Reply generated:\n{reply_content}")

            # Create draft in the same email thread
            create_draft(creds, email_from, f"Re: {email_subject}", reply_content, thread_id)

            # Add email to the processed list and save it
            processed_emails.append(msg['id'])

        # Save the updated processed emails list
        save_processed_emails(processed_emails)

    except Exception as e:
        print(f"An error occurred while auto-replying: {e}")

# Authenticate and process the last two unread emails
creds = authenticate_gmail()
auto_reply_to_last_two_unread_emails(creds)
