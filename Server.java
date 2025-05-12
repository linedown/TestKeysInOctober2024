import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;
import java.util.Base64;
import java.util.Scanner;
public class Server {
	private static ServerSocket serverConn;
	private static Socket clientConn;
    public static void main(String[] args) throws Exception{
			try{
				// Генерация пары ключей RSA
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(2048);
				KeyPair kp = kpg.generateKeyPair();
				// Преобразование массива байтов в строку с помощью техники кодирования Base64
				byte[] pkb = kp.getPublic().getEncoded();
				String pkStr = Base64.getEncoder().encodeToString(pkb);
				// Запись публичного ключа в файл
				PrintWriter pw = new PrintWriter("KeyPublic.txt", "UTF-8");
				pw.println(pkStr);
				pw.close();
				// Создание сокета
				serverConn = new ServerSocket(8080);
				System.out.println("Сервер запущен!");
				System.out.println("Публичный ключ записан в файл!!!");
				// Принятие соединения от клиента. Ввод сообщения на стороне сервера
				clientConn = serverConn.accept();
				System.out.println("Подключен какой-то рандом: " + clientConn.getInetAddress());
				System.out.println("Введите сообщение, которое будет зашифровано клиенту: ");
				String message = (new Scanner(System.in)).nextLine();
				// Получение данных от клиента
				ObjectInputStream ois = new ObjectInputStream(clientConn.getInputStream());
				byte[] data = (byte[]) ois.readObject();
				// Развёртка симметричного ключа
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
				SecretKey sk = (SecretKey) cipher.unwrap(data, "AES", Cipher.SECRET_KEY);
				// Шифрование введённого сообщения симметричных ключом
				cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.ENCRYPT_MODE, sk);
				byte[] encrMsg = cipher.doFinal(message.getBytes());
				// Отправление зашифрованного сообщения клиенту
				ObjectOutputStream oos = new ObjectOutputStream(clientConn.getOutputStream());
				oos.writeObject(encrMsg);
				// После этого соединения закрываются
				clientConn.close();
				serverConn.close();
				System.out.println("Связь с клиентом завершена!");
			} catch(Exception e){
				System.out.println("Ашипка в виде английских слов: " + e.getMessage());
			}
    }
}