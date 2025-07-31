import smtplib
from email.mime.text import MIMEText

# Edit these as per your setup
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_SENDER = 'youraddress@gmail.com'
EMAIL_PASSWORD = 'your-app-password'      # Use an app password, not your real password

def send_email_alert(to_email, item_name, current_qty, min_threshold):
    subject = f"Low Stock Alert: {item_name}"
    body = f"Attention:\n\nThe item '{item_name}' is low in stock.\n\nCurrent quantity: {current_qty}\nMinimum threshold: {min_threshold}\nPlease restock soon.\n\n-- Smart Inventory Manager"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = to_email

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, to_email, msg.as_string())
        server.quit()
        print("Low stock alert email sent to", to_email)
    except Exception as e:
        print("Could not send email:", e)

# Example usage:
# send_email_alert('recipient@example.com', 'Soap', 3, 10)
