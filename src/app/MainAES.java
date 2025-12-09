package app;

/**
 * Test des méthodes de la classe "ChiffrementAES" et "CleSecreteManager".
 *
 * @author
 */
public class MainAES {

    public static void main(String[] args) {

        String exp = "rendez-vous à 06h30, amis de la pêche en Gruyère !";
        String cle = "PabloPicasso";

        try {
            // IMPORTANT : Ne modifier pas ce qui précéde..

            System.out.println("=== TEST AES AVEC CLÉ INVENTÉE ===");

            // 1) Normaliser et encoder la clé en Base64
            String cleBase64 = ChiffrementAES.normaliserEncoderBase64(cle);
            System.out.println("Clé normalisée + Base64 : " + cleBase64);

            // 2) Chiffrement avec la clé normalisée
            String crypte = ChiffrementAES.encrypter(exp, cleBase64);
            System.out.println("Texte encrypté Base64 : " + crypte);

            // 3) Décryptage avec la même clé
            String decrypte = ChiffrementAES.decrypter(crypte, cleBase64);
            System.out.println("Texte décrypté : " + decrypte);


            System.out.println("\n=== TEST AES AVEC CLÉ SECRÈTE (secret.key) ===");

            // 4) Chiffrement avec clé venant du fichier secret.key
            String crypte2 = ChiffrementAES.encrypter(exp);
            System.out.println("Texte encrypté avec clé fichier : " + crypte2);

            // 5) Décryptage avec la clé venant du fichier secret.key
            String decrypte2 = ChiffrementAES.decrypter(crypte2);
            System.out.println("Texte décrypté avec clé fichier : " + decrypte2);

            // IMPORTANT : Ne modifier pas ce qui suit...

        } catch (Exception ex) {
            System.out.println("Erreur : " + ex.getMessage());
        }
    }

}
