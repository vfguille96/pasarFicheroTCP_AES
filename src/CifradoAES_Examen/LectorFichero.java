package CifradoAES_Examen;

import java.io.*;

class LectorFichero {
    private InputStream is;
    private BufferedReader buf;

    String getHashFicheroLeido() {
        return hashFicheroLeido;
    }

    private String hashFicheroLeido;

    LectorFichero(String rutaFichero) {
        try {
            is = new FileInputStream(rutaFichero);
            buf = new BufferedReader(new InputStreamReader(is));
        } catch (FileNotFoundException e) {
            System.out.println("El fichero no existe o no está disponible.");
        }
    }

    String leer() {
        StringBuilder sb = new StringBuilder();
        String line;
        try {
            while ((line = buf.readLine()) != null) {
                sb.append(line).append("\n");
            }

            hashFicheroLeido = CifrarYDescifrar.obtenerHashDesdeString(sb.toString());

        } catch (Exception e) {
            System.out.println("Error al leer el fichero. Leido hasta el momento: " + sb.toString());
        }

        return sb.toString();
    }

    void cerrarFlujosFichero() {
        if (is != null) {
            try {
                is.close();
                is = null;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        if (buf != null) {
            try {
                buf.close();
                buf = null;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
