import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;


public class TOTP {

    private TOTP() {}



    private static byte[] hmac_sha(String crypto, byte[] keyBytes,
                                   byte[] text){
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey =
                    new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }



    private static byte[] hexStr2Bytes(String hex){
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex,16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        System.arraycopy(bArray, 1, ret, 0, ret.length);
        return ret;
    }

    private static final int[] DIGITS_POWER
            // 0 1  2   3    4     5      6       7        8
            = {1,10,100,1000,10000,100000,1000000,10000000,100000000 };


    public static String generateTOTP(String key,
                                      String time,
                                      String returnDigits){
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }



    public static String generateTOTP256(String key,
                                         String time,
                                         String returnDigits){
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }


    public static String generateTOTP(String key,
                                      String time,
                                      String returnDigits,
                                      String crypto){
        int codeDigits = Integer.decode(returnDigits);
        StringBuilder result;

        // Using the counter
        // First 8 bytes are for the movingFactor
        StringBuilder timeBuilder = new StringBuilder(time);
        while (timeBuilder.length() < 16 )
            timeBuilder.insert(0, "0");
        time = timeBuilder.toString();

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(time);
        byte[] k = hexStr2Bytes(key);


        byte[] hash = hmac_sha(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary =
                ((hash[offset] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8) |
                        (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = new StringBuilder(Integer.toString(otp));
        while (result.length() < codeDigits) {
            result.insert(0, "0");
        }
        return result.toString();
    }

    public static void main(String[] args) {
        // Seed for HMAC-SHA1 - 20 bytes
        String seed = "3132333435363738393031323334353637383930";
        // Seed for HMAC-SHA256 - 32 bytes
        String seed32 = "3132333435363738393031323334353637383930" +
                "313233343536373839303132";
        // Seed for HMAC-SHA512 - 64 bytes
        String seed64 = "3132333435363738393031323334353637383930" +
                "3132333435363738393031323334353637383930" +
                "3132333435363738393031323334353637383930" +
                "31323334";

        long X = 30;
        String steps;
        long time = Instant.now().getEpochSecond()/X;
        System.out.println(time);
        steps = Long.toHexString(time).toUpperCase();
        System.out.println(generateTOTP(seed64, steps, "6",
                "HmacSHA512"));

        }

    }
