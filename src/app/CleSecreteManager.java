package app;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Encoder;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Permet de créer et gérer une clé secrète unique pour AES. Cette clé est
 * stockée dans un fichier "secret.key" à la racine de l'application.
 *
 * @author Jean-Claude Stritt
 */
public class CleSecreteManager {

  private static CleSecreteManager instance = null;

  private static final String CHEMIN_VERS_CLE = "secret.key";
  private static final String CLE_DEFAUT = "0123456789ABCaDEF";
  private static final String TYPE_CHIFFREMENT = "AES";

  private CleSecreteManager() {
    generer();
  }

  /**
   * Méthode getIntance pour récupérer une instance unique de cette classe, car
   * celle-ci est implémentée comme un "singleton".
   *
   * @return une instance de cette classe
   */
  public synchronized static CleSecreteManager getInstance() {
    if (instance == null) {
      instance = new CleSecreteManager();
    }
    return instance;
  }

  /**
   * Teste si le fichier pour la clé secrète existe déjà.
   *
   * @param fName le nom du fichier à tester
   * @return true s'il n'existe pas encore
   */
  private boolean fichierExistePas(String fName) {
    File f = new File(fName);
    return !f.exists();
  }

  /**
   * Génère une clé et la sauve dans le fichier "secret.key".
   */
  private void generer() {
    try {
      SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
      byte[] bytes = new byte[256];
      secureRandom.nextBytes(bytes);

      KeyGenerator keyGen = KeyGenerator.getInstance(TYPE_CHIFFREMENT);
      keyGen.init(secureRandom);
      SecretKey cleSecrete = keyGen.generateKey();
      sauver(cleSecrete.getEncoded());
    } catch (NoSuchAlgorithmException ex) {
      System.out.println(ex.getMessage());
    }
  }

  /**
   * Sauve la clé secrète générée dans un fichier "secret.key".
   *
   * @param keyBytes la clé secrète sous la forme d'un tableau d'octets
   */
  private void sauver(byte[] keyBytes) {
    if (fichierExistePas(CHEMIN_VERS_CLE)) {
      FileOutputStream fos;
      try {
        fos = new FileOutputStream(CHEMIN_VERS_CLE);
        Encoder encodeur = Base64.getEncoder();
        String b64 = encodeur.encodeToString(keyBytes);
        fos.write(b64.getBytes());
        fos.close();
      } catch (FileNotFoundException ex) {
      } catch (IOException ex) {
      }
    }
  }

  /**
   * Permet de lire la clé secrète depuis le fichier créé.
   *
   * @return la clé secrète sous la forme d'un String encodé Base64
   */
  public String lire() {
    String cleSecrete = "";
    try {
      File file = new File(CHEMIN_VERS_CLE);
      FileInputStream fis = new FileInputStream(file);
      byte[] cleOctets = new byte[(int) file.length()];
      fis.read(cleOctets);
      fis.close();
      cleSecrete = new String(cleOctets);
    } catch (FileNotFoundException ex) {
    } catch (IOException ex) {
    }
    return cleSecrete;
  }
}
