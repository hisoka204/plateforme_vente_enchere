import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

def send_verification_email(email, code):
    sender_email = "sangarebademba.mail@gmail.com"
    sender_password = "nqzg loqf ojju cvyg"
    subject = "8Auctions - Votre code de vérification"
    body = f"Code de vérification pour 8Auctions à 6 chiffres:\n\n{code}\n\nVeuillez l'entrer dans la fenêtre dédiée.\n\nSi vous ne voyez plus cette fenêtre, veuillez vous connecter dans l'onglet 'Se connecter' et un nouveau code de vérification vous sera réenvoyé.\n\n8Auctions"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, email, text)
        server.quit()
        print("Email envoyé avec succès")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")

def generate_verification_code():
    return str(random.randint(100000, 999999))
