package encryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class SymmetricImageDecryption {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec("password_clase_seguridad_en_redes".toCharArray(), Base64.getDecoder().decode("eLrnNGRtUfg="), 10, 256);
        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode("OU6nuF1j6UESQFy+sGd0ew=="));

        Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher2.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedImage = cipher2.doFinal(
                Files.readAllBytes(Paths.get("spidertocat_encrypted.png")));

        try (FileOutputStream fos =
                     new FileOutputStream(
                             Paths.get("spidertocat_decrypted.png").toFile())) {
            fos.write(decryptedImage);
        }

    }

}
