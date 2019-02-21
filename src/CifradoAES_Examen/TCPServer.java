package CifradoAES_Examen;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static CifradoAES_Examen.CifrarYDescifrar.*;

public class TCPServer {
    private String mensaje;
    private String hashArchivoLeido;
    private ServerSocket serverSocket;
    private LectorFichero lectorFichero;
    private KeyPair parDeClavesServidor;

    private TCPServer(int port, String rutaFichero) {
        try {
            //Crear socket del servidor
            serverSocket = new ServerSocket(port);

            lectorFichero = new LectorFichero(rutaFichero);
            mensaje = lectorFichero.leer();
            lectorFichero.cerrarFlujosFichero();
            generarParDeClavesServidor();

            System.out.println("Atendiendo solicitudes mediante el puerto: " + serverSocket.getLocalPort());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        final int port = 33060;
        try {
            TCPServer tcpServer = new TCPServer(port, "texto.txt");
            while (true) {
                tcpServer.Start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void generarParDeClavesServidor() throws NoSuchAlgorithmException {
        parDeClavesServidor = CifrarYDescifrar.generarClaveRSA();
    }

    public void Start() {
        try {
            Socket socket = serverSocket.accept();

            System.out.println("Recibida conexión con el cliente " + socket.getRemoteSocketAddress());

            DataOutputStream enviarTextoACliente = new DataOutputStream(socket.getOutputStream());
            ObjectInputStream recibirClavePublicaDeCliente = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream enviarClavePublicaACliente = new ObjectOutputStream(socket.getOutputStream());
            DataInputStream recibirTextoDeCliente = new DataInputStream(socket.getInputStream());

            //Enviar clave pública del Servidor al Cliente                                                              1
            enviarClavePublicaACliente.writeObject(parDeClavesServidor.getPublic());

            //Recibir clave pública del cliente                                                                         4
            Key clavePublicaCliente = (Key) recibirClavePublicaDeCliente.readObject();

            //Recibir clave simetrica cifrada con la clave pública del servidor y descifra con la privada.              6
            String claveSimetricaClienteEncrip = recibirTextoDeCliente.readUTF();
            String claveSimetricaCliente = CifrarYDescifrar.desencriptarRSA(claveSimetricaClienteEncrip, parDeClavesServidor.getPrivate());

            //Encriptar clave simétrica con clave pública del Cliente
            String claveSimetricaEncriptadaDelServidor = CifrarYDescifrar.encriptarRSA(claveSimetricaCliente, clavePublicaCliente);
            enviarTextoACliente.writeUTF(claveSimetricaEncriptadaDelServidor);

            System.out.println("\nEstablecida conexión cifrada segura (candadito cerrado).");

            //Encriptar fichero leido con clave obtenida
            String mensajeEncriptado = encriptarAES(mensaje, claveSimetricaCliente);

            //Enviar mensaje encriptado al cliente
            enviarTextoACliente.writeUTF(mensajeEncriptado);
            enviarTextoACliente.writeUTF(lectorFichero.getHashFicheroLeido());
            hashArchivoLeido = lectorFichero.getHashFicheroLeido();

            //Recibir hash del cliente para comparar con el calculado al leer el archivo
            String hashCliente = recibirTextoDeCliente.readUTF();

            //mostrarDatosAdicionales(mensajeEncriptado, hashCliente);

            compararHashClienteServidor(hashCliente);

            //String mensajeCliente = recibirTextoDeCliente.readUTF();
            // System.out.println("Mensaje descifrado del cliente: " + CifrarYDescifrar.desencriptarAES(mensajeCliente, claveSimetricaCliente));

            // Cerrar flujos
            cerrarFlujos(enviarTextoACliente, recibirClavePublicaDeCliente, enviarClavePublicaACliente, recibirTextoDeCliente);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void compararHashClienteServidor(String hashCliente) {
        if (hashCliente.equals(hashArchivoLeido))
            System.out.println("\n\n********* Archivo enviado y recibido satisfactoriamente *********");
        else
            System.out.println("\n\n######### Error al transmitir el fichero #########");
    }

    private void cerrarFlujos(DataOutputStream enviarTextoACliente, ObjectInputStream recibirClavePublicaDeCliente, ObjectOutputStream enviarClavePublicaACliente, DataInputStream recibirTextoDeCliente) throws IOException {
        enviarClavePublicaACliente.close();
        recibirTextoDeCliente.close();
        recibirClavePublicaDeCliente.close();
        recibirTextoDeCliente.close();
        enviarTextoACliente.close();
    }

    private void mostrarDatosAdicionales(String mensajeEncriptado, String hashCliente) {
        System.out.println("Texto leido descifrado:\n" + mensaje);
        System.out.println("Texto leido cifrado a enviar:\n" + mensajeEncriptado);
        System.out.println("Hash del texto leido: " + hashArchivoLeido);
        System.out.println("Hash recibido del cliente: " + hashCliente);
    }
}