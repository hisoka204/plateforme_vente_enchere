import socket
import sqlite3
import threading
from rsa import gen_rsa_keypair, rsa_enc, rsa_dec, rsa_sign, rsa_verify
from communicate import send_rsa, recv_rsa, send_aes, recv_aes
import pickle
import struct
from hash import create_hashed_password, verify_password, create_hashed_code # Import des fonctions de hashage
import re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from datetime import datetime, timedelta
import time
from send_email import *
from aes import encrypt_data_with_aes, decrypt_data_with_aes


# Clés RSA pour le serveur
server_private_key, server_public_key = ((126464878710188379211830495468211670748012661459957403391898780966552219806233570410424113413364278861896977028109947073003490289793553656685478004493825528988062680692706952018900117764582125770339942530055595310363082030123111913400894613348989013935604300493205702263084867560574011426277255228298193232429, 65537),(126464878710188379211830495468211670748012661459957403391898780966552219806233570410424113413364278861896977028109947073003490289793553656685478004493825528988062680692706952018900117764582125770339942530055595310363082030123111913400894613348989013935604300493205702263084867560574011426277255228298193232429, 45212202392232078443218159342359269506171119489857667599557325450452698629172109719948074786382120843710364706480553884377859491430229674476108910162050927120528364908957225359343917048828282434038434827844103146506585531851760333851237853920988652409340039278507920152330726489631945930907262433756621414273))
utilisateur_verrifier = {}

HOST = '127.0.0.1'
PORT = 6589

def compare_time(auction_id, conn_db):
    """Compare le temps actuel avec le temps d'expiration d'une enchère."""
    cursor = conn_db.cursor()
    cursor.execute("SELECT expiration_date FROM auctions WHERE id=?", (auction_id,))
    expiration_date = cursor.fetchone()[0]
    if expiration_date:
        expiration_date = datetime.strptime(expiration_date, '%d/%m/%Y %H:%M:%S')
        current_time = datetime.now()
        if current_time > expiration_date:
            return True # L'enchère est expirée
        else: 
            return False # L'enchère n'est pas encore expirée
    else:
        return None # Enchère non trouvée

def handle_client(conn, addr):
    """Gère les connexions persistantes pour un client."""
    print(f"Connexion de la socket : {addr}")

    conn_db = sqlite3.connect('data.db')
    cursor = conn_db.cursor()

    try:
        # Réception clé publique
        client_public_key = pickle.loads(conn.recv(4096))
        username = None
        while True:
            command = recv_rsa(client_public_key, server_private_key, conn)
            if not command:
                break

            # Inscription de l'utilisateur
            if command.startswith("USER"):
                parts = command.split()
                if len(parts) < 5:
                    response_message = "ERR_012"
                else:
                    username = parts[1]
                    password = parts[2]
                    confirm_password = parts[3]
                    email = parts[4]
                    if len(username) > 25:
                        response_message = "ERR_025"
                    elif not username:
                        response_message = "ERR_012"
                    elif not re.match(r'^[a-zA-Z0-9_.]+$', username):
                        response_message = "ERR_007"
                    elif not password or not confirm_password:
                        response_message = "ERR_012"
                    elif password != confirm_password:
                        response_message = "ERR_014"
                    elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                        response_message = "ERR_027"
                    else:
                        print(f"SR_USER: Tentative d'inscription avec le nom d'utilisateur '{username}' depuis {addr}")
                        cursor.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
                        user_exists = cursor.fetchone()

                        if user_exists:
                            response_message = "ERR_021"
                        else:
                            if not (8 <= len(password) <= 40):
                                response_message = "ERR_015"
                            elif not any(char.isupper() for char in password):
                                response_message = "ERR_016"
                            elif not any(char.islower() for char in password):
                                response_message = "ERR_017"
                            elif not any(char.isdigit() for char in password):
                                response_message = "ERR_018"
                            elif not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
                                response_message = "ERR_019"
                            else:
                                hashed_password, salt = create_hashed_password(password)
                                verification_code = generate_verification_code()
                                verif_code = create_hashed_code(verification_code, salt)
                                cursor.execute("INSERT INTO users (username, password, salt, email, verification_code) VALUES (?, ?, ?, ?, ?)",
                                               (username, hashed_password, salt, email, verif_code))
                                conn_db.commit()
                                send_verification_email(email, verification_code)
                                response_message = "SR_INSC"

                send_rsa(response_message, client_public_key, server_private_key, conn)

            # Connexion de l'utilisateur à la BDD une fois qu'il est inscrit
            elif command.startswith("LOGI"):
                parts = command.split()
                if len(parts) < 3:
                    response_message = "ERR_011"
                else:
                    username = parts[1]
                    password = parts[2]
                    if not username or not password:
                        response_message = "ERR_011"
                    else:
                        print(f"SR_LOGI: Tentative de connexion pour '{username}' depuis {addr}")
                        cursor.execute("SELECT password, salt, is_verified, email FROM users WHERE username=?", (username,))
                        user = cursor.fetchone()

                        if user:
                            stored_hash, salt, is_verified, email = user
                            if verify_password(password, salt, stored_hash):
                                if is_verified:
                                    response_message = "SR_CONN"
                                    utilisateur_verrifier[username] = client_public_key
                                else:
                                    verification_code = generate_verification_code()
                                    verif_code = create_hashed_code(verification_code, salt)
                                    cursor.execute("UPDATE users SET verification_code=? WHERE username=?", (verif_code, username))
                                    conn_db.commit()
                                    send_verification_email(email, verification_code)
                                    response_message = "SR_VERISVP"
                            else:
                                response_message = "ERR_006"
                                time.sleep(2)
                        else:
                            response_message = "ERR_020"
                            time.sleep(2)

                send_rsa(response_message, client_public_key, server_private_key, conn)

            elif command.startswith("VERI"):
                parts = command.split()
                if len(parts) < 3:
                    response_message = "ERR_012"
                else:
                    username = parts[1]
                    code = parts[2]
                    cursor.execute("SELECT verification_code,salt FROM users WHERE username=?", (username,))
                    stored_code,salt = cursor.fetchone()

                    if verify_password(code, salt, stored_code):
                        cursor.execute("UPDATE users SET is_verified=1 WHERE username=?", (username,))
                        conn_db.commit()
                        
                        response_message = "SR_VERI"
                    else:
                        response_message = "ERR_026"

                send_rsa(response_message, client_public_key, server_private_key, conn)

            elif command.startswith("ENID"):
                parts = command.split()
                if len(parts) < 2:
                    response_message = "ERR_013"
                else:
                    title = parts[1]
                    if not title:
                        response_message = "ERR_013"
                    else:
                        print(f"SR_TIT: Titre de l'enchère reçu - '{title}' depuis {addr}")
                        response_message = f"SR_TIT: Titre reçu"
                send_rsa(response_message, client_public_key, server_private_key, conn)

            elif command.startswith("DATE"):
                date_actuelle_server = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                creation_date = date_actuelle_server
                print(f"SR_DAT: Date de mise en ligne reçue - '{creation_date}' depuis {addr}")
                response_message = f"SR_DAT: Date reçue {creation_date}"
                send_rsa(response_message, client_public_key, server_private_key, conn)

            elif command.startswith("EXPI"):
                parts = command.split()
                if len(parts) < 3:
                    response_message = "ERR_013"
                else:
                    expiration_date = f"{parts[1]} {parts[2]}"
                    if not expiration_date:
                        response_message = "ERR_013"
                    else:
                        print(f"SR_EXP: Date d'expiration reçue - '{expiration_date}' depuis {addr}")
                        response_message = f"SR_EXP: Date d'expiration reçue"
                send_rsa(response_message, client_public_key, server_private_key, conn)

            elif command.startswith("DESC"):
                parts = command.split()
                if len(parts) < 2:
                    response_message = "ERR_013"
                else:
                    description = parts[1]
                    if not description:
                        response_message = "ERR_013"
                    else:
                        print(f"SR_ESC: Description de l'enchère reçue - '{description}' depuis {addr}")
                        response_message = f"SR_ESC: Description reçue"
                send_rsa(response_message, client_public_key, server_private_key, conn)

            # Gestion des enchères
            elif command.startswith("EVAL"):
                parts = command.split(maxsplit=1) # Split avec maxsplit pour éviter de couper la description ou le titre
                if len(parts) < 2:
                    response_message = "ERR_022"
                else:
                    price = parts[1].strip()

                    # Validation manuelle du prix
                    if len(price) > 10:
                        response_message = "ERR_022"
                    else:
                        is_valid_price = True
                        dot_count = 0

                        for char in price:
                            if char == '.':
                                dot_count += 1
                                if dot_count > 1: # Plus d'un point n'est pas autorisé
                                    is_valid_price = False
                                    break
                            elif not char.isdigit(): # Vérifie que les autres caractères sont des chiffres
                                is_valid_price = False
                                break
                        
                        # Vérifier si le prix est valide et ne commence/termine pas par un point
                        if not is_valid_price or price.startswith('.') or price.endswith('.'):
                            response_message = "ERR_022"
                        else:
                            print(f"SR_EVA: Valeur de l'enchère reçue - '{price}' depuis {addr}")

                            # Vérification des contraintes de titre et description
                            if (
                                title and len(title) <= 100 and # Titre max 100 caractères
                                description and len(description) <= 300 and # Description max 300 caractères
                                creation_date and expiration_date and username
                            ):
                                try:
                                    # Convertir expiration_date en objet datetime
                                    date_actuelle_server = datetime.now()
                                    expiration_datetime = datetime.strptime(expiration_date, "%d/%m/%Y %H:%M:%S")

                                    # Vérifier si la date d'expiration est supérieure à la date actuelle
                                    if expiration_datetime <= date_actuelle_server:
                                        response_message = "ERR_008"
                                    # Vérifier si l'intervalle est d'au moins 1 minute
                                    elif (expiration_datetime - date_actuelle_server).total_seconds() < 60:
                                        response_message = "ERR_008"
                                    else:
                                        # Récupérer l'ID de l'utilisateur
                                        cursor.execute("SELECT id FROM users WHERE username=?", (username,))
                                        user_id = cursor.fetchone()[0]

                                        # Sinon, on insère dans la BDD
                                        is_expired = 0
                                        cursor.execute(
                                            "INSERT INTO auctions (title, description, creation_date, expiration_date, expired, price, current_price, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                            (title, description, creation_date, expiration_date, is_expired, price, price, user_id)
                                        )
                                        conn_db.commit()
                                        response_message = "SR_ENCH: L'enchère a bien été créée !"
                                except ValueError:
                                    response_message = "ERR_008"
                                except Exception as e:
                                    response_message = f"ERR_004: {e}"
                            else:
                                # Gestion des erreurs pour le titre ou la description
                                if not title or len(title) > 100:
                                    response_message = "ERR_023"
                                elif not description or len(description) > 300:
                                    response_message = "ERR_024"
                                else:
                                    response_message = "ERR_010" # Autre problème

                send_rsa(response_message, client_public_key, server_private_key, conn)

            elif command.startswith("LIST"):
                cursor.execute("SELECT id, title, description, creation_date, expiration_date, current_price, user_id, last_bidder_id FROM auctions WHERE expired = 0")
                active_auctions = cursor.fetchall()
                cursor.execute("SELECT id, title, description, creation_date, expiration_date, current_price, user_id, last_bidder_id FROM auctions WHERE expired = 1")
                expired_auctions = cursor.fetchall()

                response_message_parts = []

                if active_auctions:
                    response_message_parts.append("Enchères en cours:")
                    response_message_parts.extend(
                        [f"ID: {row[0]}, Titre: {row[1]}, Description: {row[2]}, Date: {row[3]}, Expiration: {row[4]}, Prix: {row[5]}, Auteur: {get_username_by_id(row[6])}, Dernier enchérisseur: {get_username_by_id(row[7]) if row[7] and username and get_username_by_id(row[7]) == username else 'masqué'}"
                         for row in active_auctions]
                    )

                if expired_auctions:
                    response_message_parts.append("Enchères expirées:")
                    response_message_parts.extend(
                        [f"ID: {row[0]}, Titre: {row[1]}, Description: {row[2]}, Date: {row[3]}, Expiration: {row[4]}, Prix: {row[5]}, Auteur: {get_username_by_id(row[6])}, Dernier enchérisseur: {get_username_by_id(row[7]) if row[7] else 'Aucun'}"
                         for row in expired_auctions]
                    )

                if response_message_parts:
                    response_message = "\n".join(response_message_parts)
                else:
                    response_message = "Aucune enchère disponible."
                send_aes(response_message, client_public_key, server_private_key, conn)

            elif command.startswith("EXIT"):
                response_message = "SR_EXIT: Déconnexion réussie."
                send_rsa(response_message, client_public_key, server_private_key, conn)
                break
            elif command.startswith("BID"):
                parts = command.split()
                if len(parts) < 4:
                    response_message = "ERR_013"
                else:
                    auction_id, bid_amount, bidder = parts[1], parts[2], parts[3]
                    if not auction_id or not bid_amount or not bidder:
                        response_message = "ERR_013"
                    else:
                        if bidder in utilisateur_verrifier:
                            if client_public_key == utilisateur_verrifier[bidder]:
                                cursor.execute("SELECT current_price FROM auctions WHERE id=?", (auction_id,))

                                current_price = cursor.fetchone()[0]
                                try:
                                    if compare_time(auction_id, conn_db):
                                        response_message = "ERR_008"
                                    else:
                                        # Récupérer l'ID de l'utilisateur
                                        if float(bid_amount) > float(current_price):
                                            cursor.execute("SELECT id FROM users WHERE username=?", (bidder,))
                                            bidder_id = cursor.fetchone()[0]

                                            cursor.execute("UPDATE auctions SET current_price=?, last_bidder_id=? WHERE id=?", (bid_amount, bidder_id, auction_id))
                                            conn_db.commit()
                                            response_message = "SR_BID: Enchère mise à jour avec succès."
                                        else:
                                            response_message = "ERR_009"
                                except ValueError:
                                    response_message = "ERR_009"
                            else:
                                response_message = "ERR_002"
                        else:
                            response_message = "ERR_002"

                send_rsa(response_message, client_public_key, server_private_key, conn)

            elif command.startswith("DEL"):
                parts = command.split()
                if len(parts) < 2:
                    response_message = "ERR_002"
                else:
                    auction_id= parts[1]
                    if not auction_id:
                        response_message = "ERR_002"
                    else:
                        cursor.execute("SELECT creation_date,user_id FROM auctions WHERE id=?", (auction_id,))
                        result = cursor.fetchone()

                        if result:
                            date = result[0]
                            createur = result[1]
                            if (get_username_by_id(createur) == username):
                                if (datetime.now() - datetime.strptime(date, "%d/%m/%Y %H:%M:%S")).total_seconds() > 300:
                                    response_message = "ERR_008"
                                else:
                                        cursor.execute("DELETE FROM auctions WHERE id=?", (auction_id,))
                                        conn_db.commit()
                                        response_message = "SR_DEL"
                            else:
                                response_message = "ERR_005"
                        else:
                                response_message = "ERR_004"

                send_rsa(response_message, client_public_key, server_private_key, conn)
            else:
                response_message = "ERR_002"
                send_rsa(response_message, client_public_key, server_private_key, conn)

    except Exception as e:
        print(f"Erreur lors du traitement du client {addr} : {e}")
    finally:
        conn_db.close()
        conn.close()
        print(f"Déconnexion de la socket : {addr}")

def get_username_by_id(user_id):
    conn_db = sqlite3.connect('data.db')
    cursor = conn_db.cursor()
    cursor.execute("SELECT username FROM users WHERE id=?", (user_id,))
    username = cursor.fetchone()[0]
    conn_db.close()
    return username

def mis_a_jour_date():
    conn_db = sqlite3.connect('data.db')
    cursor = conn_db.cursor()

    while True:
        cursor.execute("SELECT id FROM auctions WHERE expired = 0")
        auction = cursor.fetchall()
        for i in auction:
            auction_id = i[0]
            compar = compare_time(auction_id, conn_db)
            if compar:
                cursor.execute("UPDATE auctions SET expired = ? WHERE id = ?", (1, auction_id))

            elif compar == False :
                cursor.execute("UPDATE auctions SET expired = ? WHERE id = ?", (0, auction_id))

            conn_db.commit() # Sauvegarde les modifications
        time.sleep(10) # Attendre 10 secondes avant de recommencer

def start_server():
    """Démarre le serveur."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Serveur démarré sur {HOST}:{PORT}")

        while True:
            mis_a_jour_date_thread = threading.Thread(target=mis_a_jour_date)
            mis_a_jour_date_thread.daemon = True
            mis_a_jour_date_thread.start()
            conn, addr = server_socket.accept()
            print(f"Nouvelle connexion acceptée : {addr}")
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()

if __name__ == '__main__':
    start_server()
