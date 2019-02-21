package CifradoAES_Examen;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;

public class CifrarYDescifrar {
    public static String encriptarAES(String textoAEncriptar, String claveAES) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Key claveSimetrica = new SecretKeySpec(Base64.getEncoder().encode(claveAES.getBytes()), 0, 16, "AES");
        aes.init(Cipher.ENCRYPT_MODE, claveSimetrica);
        byte[] encriptado = aes.doFinal(textoAEncriptar.getBytes());
        return Base64.getEncoder().encodeToString(encriptado);
    }

    public static String desencriptarAES(String textoEncriptado, String claveAES) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Key claveSimetrica = new SecretKeySpec(Base64.getEncoder().encode(claveAES.getBytes()), 0, 16, "AES");
        aes.init(Cipher.DECRYPT_MODE, claveSimetrica);
        byte[] desencriptado = aes.doFinal(Base64.getDecoder().decode(textoEncriptado));
        return new String(desencriptado);
    }

    public static String encriptarRSA(String textoAEncriptar, Key clavePrivada) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, clavePrivada);
        byte[] encriptado = rsa.doFinal(textoAEncriptar.getBytes());
        return Base64.getEncoder().encodeToString(encriptado);
    }

    public static String desencriptarRSA(String textoEncriptado, Key clavePublica) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, clavePublica);
        byte[] desencriptado = rsa.doFinal(Base64.getDecoder().decode(textoEncriptado));
        return new String(desencriptado);
    }

    public static KeyPair generarClaveRSA() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    public static String obtenerHashDesdeString(String textoAComprobar) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(textoAComprobar.getBytes());
        byte[] sha256sum = messageDigest.digest();
        return Base64.getEncoder().encodeToString(new BigInteger(1, sha256sum).toString(16).getBytes());
    }
}
