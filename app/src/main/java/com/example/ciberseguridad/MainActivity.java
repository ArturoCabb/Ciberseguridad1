package com.example.ciberseguridad;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.StrictMode;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class MainActivity extends AppCompatActivity {

    private TextView tvA, tvB, tvP, tvG, tvCS, tvPA, tvms;
    private static final String IP = "10.49.64.182";
    private static final int PORT = 8080;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        tvA = (TextView) findViewById(R.id.A);
        tvB = (TextView) findViewById(R.id.B);
        tvP = (TextView) findViewById(R.id.P);
        tvG = (TextView) findViewById(R.id.G);
        tvPA = (TextView) findViewById(R.id.PA);
        tvCS = (TextView) findViewById(R.id.CS);
        tvms = (TextView) findViewById(R.id.ms);
    }

    public void Iniciar(View view){
        // Declaración de @param P y de @param G
        final long P = 23, G = 9;
        tvP.setText("Valor de P: " + Long.toString(P));
        tvG.setText("Valor de G: " + Long.toString(G));

        String A;
        long B = 0, a = 4;

        // Delclaración de llave del cliente @param a
        tvA.setText("Llave privada A: " + Long.toString(a));
        DiffieHelman dif = new DiffieHelman();
        long x = dif.DiffieHelmanClient(G, a, P);
        A = Long.toString(x);
        tvPA.setText("Llave publica A:" + A);
        Log.println(Log.ASSERT, "OK", "Hasta aqui vamos bien");

        try {
            // Crear socket
            Socket socket = new Socket(IP, PORT);
            Log.println(Log.ASSERT, "OK", "Si se crea la conexion socket");
            // Enviar mensaje al servidor
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);
            Log.println(Log.ASSERT, "OK", "iniciando el envía");
            out.println(Long.toString(P));
            out.println(Long.toString(G));
            out.println(A);
            Log.println(Log.ASSERT, "OK", "Datos enviados");

            // Recibir mensaje
            long Bdash = 0;
            Log.println(Log.ASSERT, "OK", "Iniciando la recepcion");
            BufferedReader br = new BufferedReader(new InputStreamReader((socket.getInputStream())));
            String msg = br.readLine();
            String Bh = br.readLine();
            Log.println(Log.ASSERT, "Valor", "que tiene: " + Bh);
            if (msg != null) {
                Double b = Double.parseDouble(msg);
                B = b.longValue();
                tvB.setText("Llave publica B: " + String.valueOf(B));
                Double c = Double.parseDouble(Bh);
                Bdash = c.longValue();
            }
            else {
                tvB.setText("¡O no!");
            }
            Log.println(Log.ASSERT, "OK", "Datos recibidos");

            Log.println(Log.ASSERT, "OK", "Iniciando ultimo calculo");
            long Adash = dif.DiffieHelmanClient(B, a, P);
            Log.println(Log.ASSERT, "OK", "Se calculo el Adash");
            tvCS.setText("Código secreto: " + Long.toString(Adash));
            out.println(Long.toString(Adash));
            if (Adash == Bdash) {
                Log.println(Log.ASSERT, "verificado", "si es quien dice");
                HashSHA sha = new HashSHA();
                String myHash = HashMD2.md2Hash(1234 ,"MD2");
                String mensaje = "Yasepudo";
                String m = cifrarMensaje(myHash, mensaje);
                tvms.setText(m);
                out.println(m);
            }

            // Cerrar la transmisión
            out.close();
            br.close();
            Log.println(Log.ASSERT, "OK", "Transmisión cerrada");
            // Cerrar el socket
            socket.close();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void runServer(View view) {
        // Declaración de @param P y de @param G
        final long P = 23, G = 9;
        tvP.setText("Valor de P: " + Long.toString(P));
        tvG.setText("Valor de G: " + Long.toString(G));

        String A;
        long B = 0, a = 4;

        // Delclaración de llave del cliente @param a
        tvA.setText("Llave privada A: " + Long.toString(a));
        DiffieHelman dif = new DiffieHelman();
        long x = dif.DiffieHelmanClient(G, a, P);
        A = Long.toString(x);
        tvPA.setText("Llave publica A: " + A);


        try {
            KeyStore trusted = KeyStore.getInstance("JKS");
            Context context = null;
            InputStream in = context.getResources().openRawResource(R.raw.key); //open inputstream for keystore file in "raw" folder
            trusted.load(in, "abc123".toCharArray());                                 //load the keystore from file (using password specified when certificate was imported into keystore)
            in.close();                                                              //close inputstream
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(trusted, "abc123".toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");               //configure SSL Context to use TLS v1.2
            sslContext.init(kmf.getKeyManagers(),null,null);

            //SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) socketFactory.createSocket(IP ,PORT);
            HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
            SSLSession s = socket.getSession();

            // Verify that the certicate hostname is for server
            // This is due to lack of SNI support in the current SSLSocket.
            if (!hv.verify("192.168.1.78", s)) {
                throw new SSLHandshakeException("Expected 192.168.1.78, " +
                        "found " + s.getPeerPrincipal());
            }

            // Enviar mensaje al servidor

            PrintWriter out = new PrintWriter(socket.getOutputStream());
            //OutputStream out = socket.getOutputStream();

            out.println(Long.toString(P));
            //out.write(String.valueOf(P));
            //out.flush();
            out.println(Long.toString(G));
            //out.write(String.valueOf(G));
            //out.flush();
            out.println(A);
            //out.write(A);
            //out.flush();


            long Bdash = 0;
            // Recibir mensaje

            BufferedReader br = new BufferedReader(new InputStreamReader((socket.getInputStream())));
            String msg = br.readLine();
            String Bh = br.readLine();

            if (msg != null) {
                Double b = Double.parseDouble(msg);
                B = b.longValue();
                tvB.setText("Llave publica B: " + String.valueOf(B));
                Double c = Double.parseDouble(Bh);
                Bdash = c.longValue();
            }
            else {
                tvB.setText("¡O no!");
            }



            long Adash = dif.DiffieHelmanClient(B, a, P);

            tvCS.setText("Código secreto: " + Long.toString(Adash));
            out.println(Long.toString(Adash));
            if (Adash == Bdash) {

                HashSHA sha = new HashSHA();
                String myHash = sha.getMyHash("1.%3.VX{^9?oe%Z");
                String mensaje = "Yasepudo";
                String m = cifrarMensaje(myHash, mensaje);
                tvms.setText(m);
                out.println(m);
            }

            // Cerrar la transmisión
            out.close();
            br.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    public String cifrarMensaje(String key, String clearText) {
        System.out.println ("texto claro: " + clearText);
        CifradoDes cd = new CifradoDes();
        String c = null;
        try {
            c = cd.encryptForDES(clearText, key);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return c;
    }

    public String descifrarMensaje(String key, String secureText) {
        System.out.println ("texto cifrado: " + secureText);
        CifradoDes cd = new CifradoDes();
        String d = null;
        try {
            d = cd.decryptForDES(secureText, key);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return d;
    }
}