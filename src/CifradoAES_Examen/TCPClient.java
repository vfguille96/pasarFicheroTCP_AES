package CifradoAES_Examen;

import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static CifradoAES_Examen.CifrarYDescifrar.*;

public class TCPClient {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String hostServidor = "localhost";
        final int puerto = 33060;
        // final String claveSimetricaCliente = "Vaya melón que tiene cicerón por la noche mientras dormía";        //Clave simétrica para cifrar la conexión.
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        final String claveSimetricaCliente = secretKey.toString();

        try {
            KeyPair parClavesCliente = CifrarYDescifrar.generarClaveRSA();

            System.out.println("Estableciendo conexión con " + hostServidor + " desde el puerto " + puerto);
            Socket clienteServidor = new Socket(hostServidor, puerto);
            System.out.println("Conectado con " + clienteServidor.getRemoteSocketAddress());

            //Abrir flujos para enviar y recibir strings y objetos
            DataOutputStream enviarTextoAServidor = new DataOutputStream(clienteServidor.getOutputStream());
            DataInputStream recibirTextoDelServidor = new DataInputStream(clienteServidor.getInputStream());
            ObjectOutputStream enviarObjetoAServidor = new ObjectOutputStream(clienteServidor.getOutputStream());
            ObjectInputStream recibirObjetoDelServidor = new ObjectInputStream(clienteServidor.getInputStream());

            //Recibir clave pública del Servidor
            Key clavePublicaServidor = (Key) recibirObjetoDelServidor.readObject();
            enviarObjetoAServidor.writeObject(parClavesCliente.getPublic());
            String claveSimetricaEncriptada = CifrarYDescifrar.encriptarRSA(claveSimetricaCliente, clavePublicaServidor);
            enviarTextoAServidor.writeUTF(claveSimetricaEncriptada);

            String claveSimetricaServidorEncrip = recibirTextoDelServidor.readUTF();
            String claveSimetricaServidor = CifrarYDescifrar.desencriptarRSA(claveSimetricaServidorEncrip, parClavesCliente.getPrivate());

            System.out.println("\nEstablecida conexión cifrada segura (candadito cerrado).\n");

            //leer mensaje encriptado y leer hash generado por el Servidor por la lectura del fichero.
            String msgEncriptado = recibirTextoDelServidor.readUTF();
            String hashServidor = recibirTextoDelServidor.readUTF();

            //Desencriptar el texto leido por el servidor y cifrado mediante la clave simétrica.
            String msgDesencriptado = desencriptarAES(msgEncriptado, claveSimetricaCliente);

            //Comprobar hash del mensaje desencriptado recibido y enviarselo al servidor para que realice también la comprobación.
            String hashCliente = CifrarYDescifrar.obtenerHashDesdeString(msgDesencriptado);
            enviarTextoAServidor.writeUTF(hashCliente);

            // Muestra los datos resultantes.
            mostrarDatos(msgEncriptado, hashServidor, msgDesencriptado, hashCliente, enviarTextoAServidor, claveSimetricaServidor);

            //Cerrar flujos
            cerrarFlujos(clienteServidor, enviarTextoAServidor, enviarObjetoAServidor, recibirObjetoDelServidor, recibirTextoDelServidor);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void mostrarDatos(String msgEncriptado, String hashServidor, String msgDesencriptado, String hashCliente, DataOutputStream enviarTextoAServidor, String claveSimetricaServidor) throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        System.out.println("\n-Texto recibido cifrado:\n" + msgEncriptado);
        System.out.println("\n-Texto recibido descifrado:\n" + msgDesencriptado);
        System.out.println("-Hash del servidor: " + hashServidor);
        System.out.println("-Hash mensaje recibido: " + hashCliente);

        compararHashClienteServidor(enviarTextoAServidor, claveSimetricaServidor, hashServidor, msgDesencriptado, hashCliente);
    }

    private static void compararHashClienteServidor(DataOutputStream enviarTextoAServidor, String claveSimetricaServidor, String hashServidor, String msgDesencriptado, String hashCliente) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (hashCliente.equals(hashServidor)) {
            System.out.println("\n\n********* Archivo recibido satisfactoriamente *********");
            //enviarTextoAServidor.writeUTF(CifrarYDescifrar.encriptarAES("¡Texto recibido con éxito en el cliente!", claveSimetricaServidor));
        } else {
            System.out.println("\n\n######### Error al descargar el fichero #########");
            //enviarTextoAServidor.writeUTF(CifrarYDescifrar.encriptarAES("¡Algo ha fallado en la transferencia del texto al cliente....!", claveSimetricaServidor));
            guardarFichero(msgDesencriptado);
        }
    }

    private static void guardarFichero(String msgDesencriptado) throws IOException {
        FileOutputStream escribirFichero = new FileOutputStream(new File("ficheroDescargado"));
        escribirFichero.write(msgDesencriptado.getBytes());
        escribirFichero.close();
    }

    private static void cerrarFlujos(Socket clienteServidor, DataOutputStream enviarTextoAServidor, ObjectOutputStream enviarObjetoAServidor, ObjectInputStream recibirObjetoDelServidor, DataInputStream recibirTextoDelServidor) throws IOException {
        enviarObjetoAServidor.close();
        recibirObjetoDelServidor.close();
        recibirTextoDelServidor.close();
        enviarTextoAServidor.close();
        clienteServidor.close();
    }
}