package tkp;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class NeoBackupProperties extends JSONObject {
    public static final String KEY_IV = "iv";

    public NeoBackupProperties(String propertiesFilename) throws IOException {
        super(new String(Files.readAllBytes(Paths.get(propertiesFilename)), StandardCharsets.UTF_8));
    }

    public byte[] getIV() {
        JSONArray ivArray = this.getJSONArray(KEY_IV);
        byte[] iv = new byte[Crypto.getCipherBlockSize()];
        for (int i = 0; i < ivArray.length(); i++) {
            iv[i] = (byte) (int) ivArray.get(i);
        }
        return iv;
    }
}
