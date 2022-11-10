package com.example.ciberseguridad;

import android.util.Log;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;

public class MiHilo extends Thread {
    private static final String IP = "10.49.64.182";
    private static final int PORT = 8080;
    private Socket socket;

    public MiHilo() {
        try {
            socket = new Socket(IP, PORT);
            Log.println(Log.ASSERT, "OK", "Si se crea la conexion socket");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void escribe(String mensaje) {
        try {
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);
            Log.println(Log.ASSERT, "OK", "iniciando el envía");
            out.println(mensaje);
            Log.println(Log.ASSERT, "OK", "Datos enviados");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String imprime() {
        return "hola";
    }

    public void run() {

    }
}
