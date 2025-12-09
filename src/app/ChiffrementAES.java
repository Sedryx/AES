package app;

import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

/**
 * Permet d'encrypter et de décrypter avec l'algorithme AES.
 *
 * @author 
 * 
 */
public class ChiffrementAES {
  private static final String METHODE_CHIFFREMENT = "AES";
  private static final int LONGUEUR_CLE_BITS = 128; // 192 et 256 aussi possibles
  private static final int LONGUEUR_CLE_OCTETS = LONGUEUR_CLE_BITS / 8;
  private static final String CLE_DEFAUT = "0123456789ABCDEF";

  /**
   * Méthode privée pour encrypter/décrypter avec AES.
   *
   * @param msg le message à encrypter ou décrypter sous la forme d'un tableau d'octets
   * @param cle la clé symétrique sous la forme d'un tableau d'octets
   * @param mode Cipher.ENCRYPT_MODE ou Cipher.DECRYPT_MODE
   *
   * @return tableau d'octets encrypté ou décrypté
   * @throws Exception indique que l'opération a échoué
   */
  private static byte[] aesProcess(byte[] msg, byte[] cle, int mode) throws Exception {
    // génère une clé AES avec la clé fournie
    KeyGenerator kgen = KeyGenerator.getInstance("AES");
	  kgen.init(LONGUEUR_CLE_BITS); // 192 ou 256 bits normal. aussi possible
    SecretKeySpec keySpec = new SecretKeySpec(cle, "AES");
    
    // crée un manager de chiffrement avec la bonne méthode de chiffrement
    Cipher cipher = Cipher.getInstance(METHODE_CHIFFREMENT);
    cipher.init(mode, keySpec);
    return cipher.doFinal(msg);
  }

  /**
   * Normalise la longueur d'une clé pour AES en supprimant les caractères 
   * en trop ou en comblant ceux qui manquent.
   *
   * @param cle une clé d'encryptage en clair
   * @return la clé normalisée (ex: 16 caractères=128 bits)
   */
  private static String normaliserLongueurCle(String cle) {
    if (cle.length() > LONGUEUR_CLE_OCTETS) {
      cle = cle.substring(0, LONGUEUR_CLE_OCTETS);
    }
    StringBuilder s = new StringBuilder(cle);
    int i = s.length();
    while (s.length() < LONGUEUR_CLE_OCTETS) {
      s.append(CLE_DEFAUT.charAt(i));
      i++;
    }
    return s.toString();
  }

  /**
   * Normalise et encode en Base64 une clé d'encryptage pour qu'elle soit compatible avec
   * AES (16 caractères=256 bits dans tous les cas).
   *
   * @param cle une clé d'encryptage en clair
   * @return la clé d'encryptage normalisée et encodée en Base64
   */
  public static String normaliserEncoderBase64(String cle) {
    String cleNormalisee = normaliserLongueurCle(cle);
    Encoder encodeur = Base64.getEncoder();
    return encodeur.encodeToString(cleNormalisee.getBytes());
  }

  /**
   * Méthode qui encrypte une expression de type String avec une clé donnée qui doit ètre
   * de type Base64.
   *
   * @param exp contient l'expression en clair qu'il faut encrypter
   * @param cleBase64 la clé d'encryptage fournie au format Base64
   * @return l'expression encryptée avec AES puis encodée Base64
   * @throws Exception indique que l'encryptage a échoué
   */
  public static String encrypter(String exp, String cleBase64) throws Exception {
    Decoder decodeur = Base64.getDecoder();    
    Encoder encodeur = Base64.getEncoder();
    byte[] expBytes = exp.getBytes("UTF-8");
    byte[] keyBytes = decodeur.decode(cleBase64);
    byte[] encryptedData = aesProcess(expBytes, keyBytes, Cipher.ENCRYPT_MODE);
    return encodeur.encodeToString(encryptedData);
  }

  /**
   * Méthode qui décrypte une expression encryptée et encodée Base64 à l'aide d'une clé
   * également encodée Base64.
   *
   * @param expBase64 une expression cryptée AES et encodée Base64 qui doit être décryptée
   * @param cleBase64 la clé d'encryptage fournie au format Base64
   * @return l'expression décryptée (en clair)
   * @throws Exception indique que le décryptage a échoué
   */
  public static String decrypter(String expBase64, String cleBase64) throws Exception {
    Decoder decodeur = Base64.getDecoder();    
    byte[] expBytes = decodeur.decode(expBase64);
    byte[] keyBytes = decodeur.decode(cleBase64);
    byte[] decryptedData = aesProcess(expBytes, keyBytes, Cipher.DECRYPT_MODE);
    return new String(decryptedData, java.nio.charset.StandardCharsets.UTF_8);
  }

  /**
   * Méthode qui encrypte une expression de type String avec une clé secrète codée Base64
   * qui est stockée dans un fichier "secret.key" à la racine d'une application Java. Si
   * ce fichier n'existe pas encore avec sa clé, il sera créé à la racine de l'application.
   *
   * @param exp String qui contient l'expression qu'il faut encrypter
   * @return l'expression encryptée avec AES et encodée Base64
   * @throws Exception indique que l'encryptage a échoué
   */
  public static String encrypter(String exp) throws Exception {
    String cleSecreteBase64 = CleSecreteManager.getInstance().lire();
    if (cleSecreteBase64 == null || cleSecreteBase64.isEmpty()) {
      throw new IllegalStateException("Aucune clé secrète disponible (secret.key manquant ou vide)");
    }
    return ChiffrementAES.encrypter(exp, cleSecreteBase64);
  }

  /**
   * Méthode qui dcrypte une expression encryptée AES et encodée Base64 à l'aide d'une
   * clé secrète stockée dans le fichier "secret.key" à la racine de l'application. Ce fichier
   * doit exister avec sa clé Base64 à l'intérieur.
   *
   * @param expBase64 l'expression cryptée avec AES et encodée Base64 qu'il faut décrypter
   * @return l'expression décryptée (en clair)
   * @throws Exception indique que le décryptage a échoué
   */
  public static String decrypter(String expBase64) throws Exception {
    String cleSecreteBase64 = CleSecreteManager.getInstance().lire();
    if (cleSecreteBase64 == null || cleSecreteBase64.isEmpty()) {
      throw new IllegalStateException("Aucune clé secrète disponible (secret.key manquant ou vide)");
    }
    return ChiffrementAES.decrypter(expBase64, cleSecreteBase64);
  }

}
