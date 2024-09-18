package encryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Random;

public class SymmetricImageEncryption {
    public static void main(String[] args) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidAlgorithmParameterException,
            InvalidKeyException, IOException,
            IllegalBlockSizeException,
            BadPaddingException, InvalidKeySpecException {

        //KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        //keyGenerator.init(256);
        //SecretKey secretKey = keyGenerator.generateKey();

        byte[] salt = new byte[8];
        Random random = new Random();
        random.nextBytes(salt);

        System.out.println("SALT codificado en Base64 : " + Base64.getEncoder().encodeToString(salt));
        /**
         * Se hace uso de librerias de Java para generar una llave secreta a partir de un password
         */
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec("password_clase_seguridad_en_redes".toCharArray(), salt, 10, 256);
        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        /**
         * Se hace uso de librerias de Java para generar un Vector de Iniciación[IV] requerido por el algortimo CBC
         */
        byte[] initVector = new byte[16];
        new SecureRandom().nextBytes(initVector);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
        System.out.println("IV codificado en Base64 : " + Base64.getEncoder().encodeToString(initVector));

        /**
         * Se inicia el proceso de cifrado simetrico usando AES y CBC
         */
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        /**
         * se obtiene la direccion del archivo original a cifrar
         */
        Path pathImage = Paths.get("spidertocat.png");
        /**
         * se obtiene la imagen en forma de bytes
         */
        byte[] imageBytes = Files.readAllBytes(pathImage);
        /**
            se cifran los bytes pertenecientes a la imagen original y la ejecucion de "doFinal(bytesPorCifrar)"
            retorna un nuevo arreglo de bytes pero ya cifrados
         */
        byte[] encryptedImage = cipher.doFinal(imageBytes);
        /**
         * Se accede virtualmente a una nueva ruta donde se va a vaciar el arreglo de bytes ya cifrados en la linea anterior
         */
        Path pathImageEncrypted = Paths.get("spidertocat_encrypted.png");
        /**
         * se escribe en el nuevo archivo el arreglo de bytes cifrados
         */
        try (FileOutputStream fos =
                     new FileOutputStream(
                             pathImageEncrypted.toFile())) {
            fos.write(encryptedImage);
        }

    }
}
