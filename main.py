from aesgestion import AesGestion   # Import de la classe pour gérer AES
from hashgestion import HashGestion # Import de la classe pour gérer SHA-256
from rsagestion import RsaGestion   # Import de la classe pour gérer RSA


def main():
    print("=== DÉMO CRYPTO ===")  # Titre général

    # ----- AES -----
    aes = AesGestion()                        # Création d’un objet AES
    aes.generate_aes_key()                    # Génération d’une clé AES 256 bits
    aes.save_aes_key_to_file("aes_key.bin")   # Sauvegarde de la clé dans un fichier
    aes.load_aes_key_from_file("aes_key.bin") # Chargement de la clé depuis le fichier

    msg = "Bonjour, ceci est un test AES."    # Message à chiffrer
    chiffré = aes.encrypt_string_to_base64(msg)  # Chiffrement du message en base64
    print("\n[AES] Chiffré :", chiffré)          # Affichage du texte chiffré
    print("[AES] Déchiffré :", aes.decrypt_string_from_base64(chiffré)) # Déchiffrement et affichage

    # Écriture du message dans un fichier
    with open("message.txt", "w", encoding="utf-8") as f:
        f.write(msg)

    aes.encrypt_file("message.txt", "message.enc")       # Chiffrement du fichier texte
    aes.decrypt_file("message.enc", "message_decrypt.txt") # Déchiffrement du fichier

    # ----- HASH -----
    h = HashGestion()                                   # Création d’un objet Hash
    print("\n[HASH] Texte :", h.calculate_sha256("MotDePasse123")) # Hash d’une chaîne de caractères
    print("[HASH] Fichier :", h.calculate_file_sha256("message.txt")) # Hash d’un fichier

    # ----- RSA -----
    rsa = RsaGestion()                                    # Création d’un objet RSA
    rsa.generation_clef("public.pem", "private.pem", 2048) # Génération et sauvegarde clés RSA
    rsa.chargement_clefs("public.pem", "private.pem")      # Chargement des clés

    msg_rsa = "Bonjour avec RSA !"                        # Message à chiffrer
    chiffré_rsa = rsa.chiffrement_rsa(msg_rsa)            # Chiffrement du message
    print("\n[RSA] Chiffré :", chiffré_rsa)               # Affichage du texte chiffré
    print("[RSA] Déchiffré :", rsa.dechiffrement_rsa(chiffré_rsa)) # Déchiffrement et affichage

    rsa.chiffre_dans_fichier("Texte secret dans un fichier", "rsa_message.txt") # Chiffrement direct dans un fichier
    print("[RSA] Fichier déchiffré :", rsa.dechiffre_fichier("rsa_message.txt")) # Lecture et déchiffrement du fichier


if __name__ == "__main__":  # Point d’entrée du programme
    main()                  # Appel de la fonction principale
