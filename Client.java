import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import java.util.Base64;
import java.nio.charset.Charset;
public class Client {
	private static Socket clientConn;
	public static void main(String[] args) throws Exception {
		try{
			// Получение открытого ключа из файла
			BufferedReader br = new BufferedReader(new FileReader("KeyPublic.txt", Charset.forName("UTF-8")));
			String pkStr = br.readLine();
			br.close();
			// Расшифровка открытого ключа
			byte[] pkb = Base64.getDecoder().decode(pkStr);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pkb);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey pk = kf.generatePublic(keySpec);
			// Генерация симметричного ключа
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(128);
			SecretKey sk = kg.generateKey();
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			// Свёртка симметричного открытым ключом RSA
			cipher.init(Cipher.WRAP_MODE, pk);
			byte[] wrappedKey = cipher.wrap(sk);
			// Создание сокета от клиента
			clientConn = new Socket("localhost", 8080);
			System.out.println("Успешное подключение к серверу!!!");
			// Отправление зашифрованного симметричного ключа серверу
			ObjectOutputStream oos = new ObjectOutputStream(clientConn.getOutputStream());
			oos.writeObject(wrappedKey);
			// Получение зашифрованных данных от сервера
			ObjectInputStream ois = new ObjectInputStream(clientConn.getInputStream());
			byte[] encrMsg = (byte[])ois.readObject();
			cipher = Cipher.getInstance("AES");
			// Расшифровка переданного сообщение симметричным ключом
			cipher.init(Cipher.DECRYPT_MODE, sk);
			byte[] decrMsg = cipher.doFinal(encrMsg);
			System.out.println("Расшифрованное сообщение: " + new String(decrMsg));
			clientConn.close();
			System.out.println("Связь с сервером завершена!");
		} catch(Exception e){
			System.out.println("Ашипка в виде английских слов: " + e.getMessage());
		}
    }
}
