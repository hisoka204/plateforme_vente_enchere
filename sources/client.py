import socket
import customtkinter
from tkinter import messagebox, simpledialog
import pickle
import struct
from rsa import gen_rsa_keypair, rsa_enc, rsa_dec, rsa_dec_bytes, rsa_sign, rsa_verify
from communicate import send_rsa, recv_rsa, send_aes, recv_aes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tkinter import ttk, Spinbox
from tkcalendar import Calendar
from datetime import datetime, timedelta
from aes import encrypt_data_with_aes, decrypt_data_with_aes

HOST = '127.0.0.1'
PORT = 6589

# Générer les clés du client
client_private_key, client_public_key = gen_rsa_keypair(1024)

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("8Auctions")
        self.geometry("800x600")

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session_username = None

        try:
            self.client_socket.connect((HOST, PORT))
            self.client_socket.sendall(pickle.dumps(client_public_key))
            self.server_public_key = (126464878710188379211830495468211670748012661459957403391898780966552219806233570410424113413364278861896977028109947073003490289793553656685478004493825528988062680692706952018900117764582125770339942530055595310363082030123111913400894613348989013935604300493205702263084867560574011426277255228298193232429, 45212202392232078443218159342359269506171119489857667599557325450452698629172109719948074786382120843710364706480553884377859491430229674476108910162050927120528364908957225359343917048828282434038434827844103146506585531851760333851237853920988652409340039278507920152330726489631945930907262433756621414273)

        except Exception as e:
            messagebox.showerror("Erreur", f"Connexion au serveur impossible : {e}")
            self.destroy()
            return

        self.create_widgets()
        self.auctions_frame_horizontal = None

    def create_widgets(self):
        """Crée les onglets et widgets pour l'application."""
        self.welcome_label = customtkinter.CTkLabel(self, text="L'utilisateur n'est pas connecté", font=("Arial", 16))
        self.welcome_label.pack(pady=10)

        self.label_title = customtkinter.CTkLabel(self, text="Bienvenue", font=("Arial", 24))
        self.label_title.pack(pady=10)

        self.disconnect_button = customtkinter.CTkButton(self, text="Quitter", command=self.handle_disconnect)
        self.disconnect_button.pack(anchor="ne", padx=10, pady=10)
        
        self.tabview = customtkinter.CTkTabview(self, command=self.on_tab_selected)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=20)

        # Onglet Connexion
        self.create_login_tab()

        # Onglet Inscription
        self.create_signup_tab()

        # Onglet Nouvelle Enchère
        self.create_auction_tab()
        # Onglet Enchères en cours
        self.create_auctions_tab()

        # Onglet statistique
        self.create_auctions_stats_tab()

    def create_signup_tab(self):
        """Crée l'onglet pour l'inscription."""
        self.signup_tab = self.tabview.add("S'inscrire")

        self.signup_username_entry = customtkinter.CTkEntry(self.signup_tab, placeholder_text="Nom d'utilisateur")
        self.signup_username_entry.pack(pady=10)

        self.signup_password_entry = customtkinter.CTkEntry(self.signup_tab, placeholder_text="Mot de passe", show="*")
        self.signup_password_entry.pack(pady=10)

        self.signup_confirm_password_entry = customtkinter.CTkEntry(self.signup_tab, placeholder_text="Confirmez le mot de passe", show="*")
        self.signup_confirm_password_entry.pack(pady=10)

        self.signup_email_entry = customtkinter.CTkEntry(self.signup_tab, placeholder_text="Email")
        self.signup_email_entry.pack(pady=10)

        self.signup_button = customtkinter.CTkButton(self.signup_tab, text="S'inscrire", command=self.handle_signup)
        self.signup_button.pack(pady=10)

        self.signup_error_label = customtkinter.CTkLabel(self.signup_tab, text="")
        self.signup_error_label.pack(pady=5)

    def create_login_tab(self):
        """Crée l'onglet pour la connexion."""
        self.login_tab = self.tabview.add("Se connecter")

        self.login_username_entry = customtkinter.CTkEntry(self.login_tab, placeholder_text="Nom d'utilisateur")
        self.login_username_entry.pack(pady=10)

        self.login_password_entry = customtkinter.CTkEntry(self.login_tab, placeholder_text="Mot de passe", show="*")
        self.login_password_entry.pack(pady=10)

        self.login_button = customtkinter.CTkButton(self.login_tab, text="Se connecter", command=self.handle_login)
        self.login_button.pack(pady=10)

        self.login_error_label = customtkinter.CTkLabel(self.login_tab, text="")
        self.login_error_label.pack(pady=5)

    def create_auctions_stats_tab(self):
        """Crée l'onglet pour afficher les enchères en cours (horizontales)."""
        self.auctions_tab_stats = self.tabview.add("Statistique")

        self.auctions_canvas_stats = customtkinter.CTkCanvas(self.auctions_tab_stats, highlightthickness=0, width=780, height=220)
        self.scrollbar_stats = customtkinter.CTkScrollbar(self.auctions_tab_stats, orientation="horizontal", command=self.auctions_canvas_stats.xview)

        self.auctions_canvas_stats.configure(xscrollcommand=self.scrollbar_stats.set)
        self.auctions_canvas_stats.pack(side="top", fill="both", expand=True, padx=10, pady=10)
        self.scrollbar_stats.pack(side="bottom", fill="x")

        self.refresh_button_stats = customtkinter.CTkButton(self.auctions_tab_stats, text="Rafraîchir", command=self.refresh_auctions_stats)
        self.refresh_button_stats.pack(pady=10)


    def create_auction_tab(self):
        """Crée l'onglet pour créer une enchère avec une scrollbar verticale."""
        self.auction_tab = self.tabview.add("Nouvelle Enchère")

        # Scroll barre en Y
        self.scrollable_frame = customtkinter.CTkScrollableFrame(self.auction_tab, width=500, height=400)
        self.scrollable_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Titre de l'enchère
        auction_title_label = customtkinter.CTkLabel(self.scrollable_frame, text="Titre de l'enchère")
        auction_title_label.pack(pady=(0, 0))

        self.auction_title_entry = customtkinter.CTkEntry(self.scrollable_frame, placeholder_text="Ex: Chateau 10 pièces")
        self.auction_title_entry.pack(pady=10)

        # Date d'expiration
        auction_expiration_label = customtkinter.CTkLabel(self.scrollable_frame, text="Date d'expiration")
        auction_expiration_label.pack(pady=(0, 0))

        self.calendar = Calendar(self.scrollable_frame, date_pattern="dd/MM/yyyy")
        self.calendar.pack(pady=(5, 10))

        # Heure d'expiration
        time_label = customtkinter.CTkLabel(self.scrollable_frame, text="Temps d'expiration (HH:MM:SS)")
        time_label.pack(pady=(5, 0))

        spinbox_frame = customtkinter.CTkFrame(self.scrollable_frame)
        spinbox_frame.pack(pady=(5, 10))

        self.hour_spinbox = Spinbox(spinbox_frame, from_=0, to=23, width=3, format="%02.0f", state="readonly")
        self.hour_spinbox.pack(side="left", padx=(0, 5))

        self.minute_spinbox = Spinbox(spinbox_frame, from_=0, to=59, width=3, format="%02.0f", state="readonly")
        self.minute_spinbox.pack(side="left", padx=(0, 5))

        self.second_spinbox = Spinbox(spinbox_frame, from_=0, to=59, width=3, format="%02.0f", state="readonly")
        self.second_spinbox.pack(side="left", padx=(0, 5))

        # Description
        auction_description_label = customtkinter.CTkLabel(self.scrollable_frame, text="Description de l'enchère")
        auction_description_label.pack(pady=(0, 0))

        self.auction_description_entry = customtkinter.CTkEntry(self.scrollable_frame, placeholder_text="Ex: Chateau à la campagne")
        self.auction_description_entry.pack(pady=10)

        # Valeur de l'enchère
        auction_price_label = customtkinter.CTkLabel(self.scrollable_frame, text="Valeur de l'enchère (prix) en €")
        auction_price_label.pack(pady=(0, 0))

        self.auction_price_entry = customtkinter.CTkEntry(self.scrollable_frame, placeholder_text="Ex: 768679")
        self.auction_price_entry.pack(pady=10)

        # Bouton
        auction_button = customtkinter.CTkButton(self.scrollable_frame, text="Créer l'enchère", command=self.handle_auction)
        auction_button.pack(pady=10)

        self.auction_error_label = customtkinter.CTkLabel(self.scrollable_frame, text="")
        self.auction_error_label.pack(pady=5)

    def create_auctions_tab(self):
        """Crée l'onglet pour afficher les enchères en cours (horizontales)."""
        self.auctions_tab = self.tabview.add("Enchères en cours")

        self.auctions_canvas = customtkinter.CTkCanvas(self.auctions_tab, highlightthickness=0, width=780, height=220)
        self.scrollbar = customtkinter.CTkScrollbar(self.auctions_tab, orientation="horizontal", command=self.auctions_canvas.xview)

        self.auctions_canvas.configure(xscrollcommand=self.scrollbar.set)
        self.auctions_canvas.pack(side="top", fill="both", expand=True, padx=10, pady=10)
        self.scrollbar.pack(side="bottom", fill="x")

        self.refresh_button = customtkinter.CTkButton(self.auctions_tab, text="Rafraîchir", command=self.refresh_auctions)
        self.refresh_button.pack(pady=10)

    def refresh_auctions(self):
        """Rafraîchit la liste des enchères en cours et expirées."""
        # Récupère les enchères depuis le serveur
        send_rsa("LIST", self.server_public_key, client_private_key, self.client_socket)
        response = recv_aes(self.server_public_key, client_private_key, self.client_socket)
        if response:
            print(f"Réponse LIST : {response}") 
            lines = response.split("\n")  

            # Enlever anciennes fenêtres
            for widget in self.auctions_canvas.winfo_children():
                widget.destroy()

            # Scrollbar en tkinter
            scrollable_frame = customtkinter.CTkScrollableFrame(self.auctions_canvas, width=500, height=400)
            scrollable_frame.pack(expand=True, fill="both", padx=10, pady=10)

            active_auctions_frame = customtkinter.CTkFrame(scrollable_frame)
            active_auctions_frame.pack(fill="both", expand=True, pady=(0, 10))

            expired_auctions_frame = customtkinter.CTkFrame(scrollable_frame)
            expired_auctions_frame.pack(fill="both", expand=True)

            # Stocker enchères en cours et expirées
            active_auctions = []
            expired_auctions = []
            current_section = None

            for line in lines:
                if line.strip() == "Enchères en cours:":
                    current_section = "active"
                elif line.strip() == "Enchères expirées:":
                    current_section = "expired"
                elif line.strip() and current_section:
                    if current_section == "active":
                        active_auctions.append(line.strip())
                    elif current_section == "expired":
                        expired_auctions.append(line.strip())

            # Enchères en cours
            if active_auctions:
                active_label = customtkinter.CTkLabel(active_auctions_frame, text="Enchères en cours:", font=("Arial", 14, "bold"), text_color="#333333")
                active_label.pack(anchor="w", padx=10, pady=5)
                for auction in active_auctions:
                    parts = auction.split(", ")  # séparation par ", "
                    if len(parts) == 8:
                        self.display_auction(active_auctions_frame, parts, is_expired=False)

            # Enchères expirées
            if expired_auctions:
                expired_label = customtkinter.CTkLabel(expired_auctions_frame, text="Enchères expirées:", font=("Arial", 14, "bold"), text_color="#555555")
                expired_label.pack(anchor="w", padx=10, pady=5)
                for auction in expired_auctions:
                    parts = auction.split(", ") 
                    if len(parts) == 8:
                        self.display_auction(expired_auctions_frame, parts, is_expired=True)

            # Aucune enchère
            if not active_auctions and not expired_auctions:
                no_data_label = customtkinter.CTkLabel(scrollable_frame, text="Aucune enchère disponible.", font=("Arial", 14))
                no_data_label.pack(pady=20)

        


    def refresh_auctions_stats(self):
        """Rafraîchit la liste des enchères en cours du client seulement."""
        # Récupère les enchères depuis le serveur
        send_rsa("LIST", self.server_public_key, client_private_key, self.client_socket)
        response = recv_aes(self.server_public_key, client_private_key, self.client_socket)
        if response:
            print(f"Réponse LIST : {response}")
            lines = response.split("\n") 

            # Enlever fenetres existantes
            for widget in self.auctions_canvas_stats.winfo_children():
                widget.destroy()

            scrollable_frame = customtkinter.CTkScrollableFrame(self.auctions_canvas_stats, width=500, height=400)
            scrollable_frame.pack(expand=True, fill="both", padx=10, pady=10)

            create_auctions_frame = customtkinter.CTkFrame(scrollable_frame)
            create_auctions_frame.pack(fill="both", expand=True, pady=(0, 10))

            win_auctions_frame = customtkinter.CTkFrame(scrollable_frame)
            win_auctions_frame.pack(fill="both", expand=True)

            # Stocker enchères en cours et gagnées
            create_auctions = []
            win_auctions = []

            for line in lines:
                l = line.strip().split(", ")
                if len(l) == 8:
                    author = l[6].replace("Auteur: ", "").strip()
                    last_bidder = l[7].replace("Dernier enchérisseur: ", "").strip()
                    if author == self.session_username:
                        create_auctions.append(line.strip())
                    elif last_bidder == self.session_username:
                        win_auctions.append(line.strip())

            if create_auctions:
                active_label = customtkinter.CTkLabel(create_auctions_frame, text="Enchères créées:", font=("Arial", 14, "bold"), text_color="#333333")
                active_label.pack(anchor="w", padx=10, pady=5)
                for auction in create_auctions:
                    parts = auction.split(", ")
                    if len(parts) == 8:
                        self.display_auction_stats(create_auctions_frame, parts)

            if win_auctions:
                expired_label = customtkinter.CTkLabel(win_auctions_frame, text="Enchères gagnées:", font=("Arial", 14, "bold"), text_color="#555555")
                expired_label.pack(anchor="w", padx=10, pady=5)
                for auction in win_auctions:
                    parts = auction.split(", ")
                    if len(parts) == 8:
                        self.display_auction_stats(win_auctions_frame, parts)

            if not create_auctions and not win_auctions:
                no_data_label = customtkinter.CTkLabel(scrollable_frame, text="Aucune enchère disponible.", font=("Arial", 14))
                no_data_label.pack(pady=20)


    def display_auction(self, frame, parts, is_expired):
        auction_id = parts[0].replace("ID: ", "").strip()
        title = parts[1].replace("Titre: ", "").strip()
        description = parts[2].replace("Description: ", "").strip()
        date = parts[3].replace("Date: ", "").strip()
        expiration = parts[4].replace("Expiration: ", "").strip()
        price = parts[5].replace("Prix: ", "").strip()
        author = parts[6].replace("Auteur: ", "").strip()
        last_bidder = parts[7].replace("Dernier enchérisseur: ", "").strip()

        # Création d'une boîte pour chaque enchère
        box = customtkinter.CTkFrame(frame, border_width=1, corner_radius=10, fg_color="#f0f0f0" if not is_expired else "#d3d3d3", width=400, height=400)
        box.pack(side="left", padx=10, pady=5)

        title_label = customtkinter.CTkLabel(box, text=f"Titre : {title}", font=("Arial", 14, "bold"), text_color="#333333" if not is_expired else "#555555")
        title_label.pack(anchor="w", padx=10, pady=2)

        description_label = customtkinter.CTkLabel(box, text=f"Description : {description}", font=("Arial", 12), text_color="#555555")
        description_label.pack(anchor="w", padx=10, pady=2)

        date_label = customtkinter.CTkLabel(box, text=f"Date : {date}", font=("Arial", 12), text_color="#555555")
        date_label.pack(anchor="w", padx=10, pady=2)

        expiration_label = customtkinter.CTkLabel(box, text=f"Expiration : {expiration}", font=("Arial", 12), text_color="#555555")
        expiration_label.pack(anchor="w", padx=10, pady=2)

        price_label = customtkinter.CTkLabel(box, text=f"Prix : {price}€", font=("Arial", 12), text_color="#555555")
        price_label.pack(anchor="w", padx=10, pady=2)

        author_label = customtkinter.CTkLabel(box, text=f"Auteur : {author}", font=("Arial", 12), text_color="#555555")
        author_label.pack(anchor="w", padx=10, pady=2)

        # Afficher Gagnant au lieu de dernier enchérisseur pour les enchères expirées
        if is_expired:
            # Si aucune personne a enchéri on affiche aucun au lieu d'un none
            if last_bidder == "None":
                last_bidder = "Aucun"
            winner_label = customtkinter.CTkLabel(box, text=f"Gagnant : {last_bidder}", font=("Arial", 12), text_color="#555555")
            winner_label.pack(anchor="w", padx=10, pady=2)
        else:
            # Si la personne connectée est la personne qui a surenchéri, alors on affiche son pseudo
            if last_bidder == self.session_username:
                last_bidder = self.session_username
            # Sinon on affiche masqué car ca doit rester anonym
            else:
                last_bidder = "Masqué"
            last_bidder_label = customtkinter.CTkLabel(box, text=f"Dernier enchérisseur : {last_bidder}", font=("Arial", 12), text_color="#555555")
            last_bidder_label.pack(anchor="w", padx=10, pady=2)

        # Bouton de surenchère
        if not is_expired:
            if not self.session_username:
                bid_button = customtkinter.CTkButton(box, text="Surenchérir", state="disabled", fg_color="red")
            elif self.session_username == author:
                bid_button = customtkinter.CTkButton(box, text="Surenchérir", state="disabled", fg_color="red")
            else:
                bid_button = customtkinter.CTkButton(box, text="Surenchérir", command=lambda id=auction_id: self.handle_bid(id))
            bid_button.pack(anchor="center", padx=10, pady=5)

    def display_auction_stats(self, frame, parts):
        auction_id = parts[0].replace("ID: ", "").strip()
        title = parts[1].replace("Titre: ", "").strip()
        description = parts[2].replace("Description: ", "").strip()
        date = parts[3].replace("Date: ", "").strip()
        expiration = parts[4].replace("Expiration: ", "").strip()
        price = parts[5].replace("Prix: ", "").strip()
        author = parts[6].replace("Auteur: ", "").strip()
        last_bidder = parts[7].replace("Dernier enchérisseur: ", "").strip()

        # Création d'une boîte pour chaque enchère
        box = customtkinter.CTkFrame(frame, border_width=1, corner_radius=10, fg_color="#d3d3d3", width=400, height=400)
        box.pack(side="left", padx=10, pady=5)

        title_label = customtkinter.CTkLabel(box, text=f"Titre : {title}", font=("Arial", 14, "bold"), text_color="#555555")
        title_label.pack(anchor="w", padx=10, pady=2)

        description_label = customtkinter.CTkLabel(box, text=f"Description : {description}", font=("Arial", 12), text_color="#555555")
        description_label.pack(anchor="w", padx=10, pady=2)

        date_label = customtkinter.CTkLabel(box, text=f"Date : {date}", font=("Arial", 12), text_color="#555555")
        date_label.pack(anchor="w", padx=10, pady=2)

        expiration_label = customtkinter.CTkLabel(box, text=f"Expiration : {expiration}", font=("Arial", 12), text_color="#555555")
        expiration_label.pack(anchor="w", padx=10, pady=2)

        price_label = customtkinter.CTkLabel(box, text=f"Prix : {price}€", font=("Arial", 12), text_color="#555555")
        price_label.pack(anchor="w", padx=10, pady=2)

        author_label = customtkinter.CTkLabel(box, text=f"Auteur : {author}", font=("Arial", 12), text_color="#555555")
        author_label.pack(anchor="w", padx=10, pady=2)

        if author == self.session_username:
            if (datetime.now() - datetime.strptime(date, "%d/%m/%Y %H:%M:%S")).total_seconds() < 300:
                delete_button = customtkinter.CTkButton(box, text="Supprimer",command=lambda id=auction_id: self.handle_delete(id), fg_color="red")
                delete_button.pack(anchor="center", padx=10, pady=5)


    def handle_signup(self):
        """Gère l'inscription."""
        username = self.signup_username_entry.get()
        password = self.signup_password_entry.get()
        confirm_password = self.signup_confirm_password_entry.get()
        email = self.signup_email_entry.get()

        send_rsa(f"USER {username} {password} {confirm_password} {email}", self.server_public_key, client_private_key, self.client_socket)
        response = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
        if response == "SR_INSC":
            self.signup_error_label.configure(text="Inscription réussie. Veuillez vérifier votre email pour le code de vérification.", text_color="green")
            self.verify_user(username)
        else:
            self.signup_error_label.configure(text=self.get_error_message(response), text_color="red")

    def handle_login(self):
        """Gère la connexion."""
        username = self.login_username_entry.get()
        password = self.login_password_entry.get()

        send_rsa(f"LOGI {username} {password}", self.server_public_key, client_private_key, self.client_socket)
        response = recv_rsa(self.server_public_key, client_private_key, self.client_socket)

        if response == "SR_CONN":
            self.session_username = username
            self.login_error_label.configure(text="Connexion réussie.", text_color="green")
            self.welcome_label.configure(text=f"Bonjour {username}")
        elif response == "SR_VERISVP":
            self.login_error_label.configure(text="Veuillez vérifier votre email pour le code de vérification.", text_color="green")
            self.verify_user(username)
        else:
            self.login_error_label.configure(text=self.get_error_message(response), text_color="red")

    def verify_user(self, username):
        code = simpledialog.askstring("Vérification", "Entrez le code de vérification envoyé à votre email :")
        if code:
            send_rsa(f"VERI {username} {code}", self.server_public_key, client_private_key, self.client_socket)
            response = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
            if response == "SR_VERI":
                messagebox.showinfo("Succès", "Vérification réussie.")
                self.session_username = username
                self.welcome_label.configure(text=f"Bonjour {username}")
            else:
                # Code de vérification incorrect
                messagebox.showerror("Erreur", self.get_error_message(response))

    def handle_auction(self):
        """Gère la création d'une nouvelle enchère."""
        if not self.session_username:
            self.auction_error_label.configure(text="Veuillez vous connecter avant de créer une enchère.", text_color="red")
            return

        title = self.auction_title_entry.get()
        description = self.auction_description_entry.get()
        price = self.auction_price_entry.get()

        # Récupérer la date sélectionnée dans le calendrier
        selected_date = self.calendar.get_date()

        # Récupérer l'heure, les minutes et les secondes depuis les spinbox
        selected_hour = self.hour_spinbox.get()
        selected_minute = self.minute_spinbox.get()
        selected_second = self.second_spinbox.get()

        # Combiner la date et l'heure
        expiration_date = f"{selected_date} {selected_hour}:{selected_minute}:{selected_second}"

        send_rsa(f"ENID {title}", self.server_public_key, client_private_key, self.client_socket)
        response = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
        if not response or not response.startswith("SR_TIT"):
            self.auction_error_label.configure(text=self.get_error_message(response), text_color="red")
        send_rsa(f"DATE", self.server_public_key, client_private_key, self.client_socket)
        response = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
        if not response or not response.startswith("SR_DATE"):
            self.auction_error_label.configure(text=self.get_error_message(response), text_color="red")
        send_rsa(f"EXPI {expiration_date}", self.server_public_key, client_private_key, self.client_socket)
        response = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
        if not response or not response.startswith("SR_EXP"):
            self.auction_error_label.configure(text=self.get_error_message(response), text_color="red")
        send_rsa(f"DESC  {description}", self.server_public_key, client_private_key, self.client_socket)
        reponse = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
        if not reponse or not response.startswith("SR_ESC"):
            self.auction_error_label.configure(text=self.get_error_message(response), text_color="red")
        send_rsa(f"EVAL {price}", self.server_public_key, client_private_key, self.client_socket)
        response = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
        if not response or not response.startswith("SR_ENCH"):
            self.auction_error_label.configure(text=self.get_error_message(response), text_color="red")
            self.refresh_auctions
        else:
            self.auction_error_label.configure(text="Enchère créée avec succès.", text_color="green")

    def handle_bid(self, auction_id):
        """Gère la surenchère sur une enchère."""
        bid_amount = simpledialog.askstring("Surenchère", "Entrez le montant de votre enchère :")
        if bid_amount:
            send_rsa(f"BID {auction_id} {bid_amount} {self.session_username}", self.server_public_key, client_private_key, self.client_socket)
            response = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
            if response == "SR_BID: Enchère mise à jour avec succès.":
                messagebox.showinfo("Succès", "Votre enchère a été mise à jour avec succès.")
                self.refresh_auctions() # Rafraîchir les enchères après une surenchère réussie
            else:
                messagebox.showerror("Erreur", self.get_error_message(response))

    def handle_delete(self, auction_id):
        """Gère la suppresion d'une enchère."""
        delete = simpledialog.askstring("Supprimer", "Tapez oui si vous voulez vraiment Supprimer votre enchère")
        if delete == "oui":
            send_rsa(f"DEL {auction_id}", self.server_public_key, client_private_key, self.client_socket)
            response = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
            if response == "SR_DEL":
                messagebox.showinfo("Succès", "Votre enchère a bien été supprimer.")
                self.refresh_auctions_stats()
            else:
                messagebox.showerror("Erreur", self.get_error_message(response))

    # changement de table
    def on_tab_selected(self):
        selected_tab = self.tabview.get()
        if selected_tab == "Enchères en cours":
            self.refresh_auctions()
        elif selected_tab == "Statistique":
            self.refresh_auctions_stats()

    def on_closing(self):
        """Fermeture propre de l'application."""
        self.client_socket.close()
        self.destroy()

    def get_error_message(self, error_code):
        """Renvoie le message d'erreur correspondant au code d'erreur."""
        error_messages = {
            "ERR_001": "Erreur de connexion",
            "ERR_002": "Erreur de format de commande",
            "ERR_003": "Erreur de validation de signature",
            "ERR_004": "Erreur de base de données",
            "ERR_005": "Erreur de chiffrement/déchiffrement",
            "ERR_006": "Erreur le mot de passe est incorrect",
            "ERR_007": "Erreur de validation de nom d'utilisateur",
            "ERR_008": "Erreur de validation de date d'expiration",
            "ERR_009": "Erreur de validation de prix",
            "ERR_010": "Erreur de validation de description",
            "ERR_011": "Veuillez remplir tous les champs de connexion.",
            "ERR_012": "Veuillez remplir tous les champs d'inscription.",
            "ERR_013": "Veuillez remplir tous les champs de création d'enchère.",
            "ERR_014": "Les mots de passe ne correspondent pas.",
            "ERR_015": "Le mot de passe doit contenir entre 8 et 40 caractères.",
            "ERR_016": "Le mot de passe doit contenir au moins une lettre majuscule.",
            "ERR_017": "Le mot de passe doit contenir au moins une lettre minuscule.",
            "ERR_018": "Le mot de passe doit contenir au moins un chiffre.",
            "ERR_019": "Le mot de passe doit contenir au moins un caractère spécial.",
            "ERR_020": "L'utilisateur n'existe pas.",
            "ERR_021": "Le nom d'utilisateur ou l'adresse email existe déjà. Veuillez choisir un autre nom d'utilisateur ou adresse email.",
            "ERR_022": "Veuillez entrer un prix correct (max 10 chiffres et 1 point).",
            "ERR_023": "Titre invalide (max 100 caractères)",
            "ERR_024": "Description invalide (max 300 caractères)",
            "ERR_025": "Nom d'utilisateur invalide (max 25 caractères)",
            "ERR_026": "Code de vérification incorrect.",
            "ERR_027": "Email invalide."
        }
        return error_messages.get(error_code, "Erreur inconnue")
    
    def handle_disconnect(self):
        """ déconnexion client."""
        send_rsa(f"EXIT", self.server_public_key, client_private_key, self.client_socket)
        mess = recv_rsa(self.server_public_key, client_private_key, self.client_socket)
        if mess == "SR_EXIT: Déconnexion réussie.":
            messagebox.showinfo("Déconnexion", "Déconnexion réussie.")
            self.session_username = None
            self.welcome_label.configure(text="L'utilisateur n'est pas connecté")
            self.client_socket.close()
            self.destroy()
        else:
            messagebox.showerror("Erreur", self.get_error_message(mess))
            
if __name__ == '__main__':
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
