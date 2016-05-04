package de.uni_hamburg.informatik.svs.simplepwcracker;

import com.google.common.base.Charsets;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Chars;

import java.nio.CharBuffer;
import java.util.Arrays;

public class SimplePasswordCracker {

    private static final String SALT                = "8kofferradio";
    private static final String HASH                = "2b2935865b8a6749b0fd31697b467bd7";
    private static final String CHARSET             = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final long   PASSWORD_MAX_LENGTH = 6;

    public static void main(String[] args) {
        System.out.println("Password: " + bruteForcePassword(SALT, HASH, CHARSET, PASSWORD_MAX_LENGTH));
    }

    // --------------------------------------------- SimplePasswordCracker ---------------------------------------------

    private final String       salt;
    private final HashCode     hash;
    private final char[]       charset;
    private final HashFunction md5;

    private SimplePasswordCracker(String salt, String hash, String charset) {
        this.salt    = salt;
        this.hash    = HashCode.fromString(hash);
        this.charset = charset.toCharArray();
        this.md5     = Hashing.md5();
    }

    private String run(long pwMaxLength) {
        char[]   password = "".toCharArray();
        HashCode result;

        while (password.length <= pwMaxLength) {
            result = this.md5.newHasher()
                    .putString(this.salt, Charsets.UTF_8)
                    .putString(CharBuffer.wrap(password), Charsets.UTF_8)
                    .hash();
            if (this.hash.equals(result)) {
                return new String(password);
            }
            password = increment(password, 0);
        }

        return "Not found";
    }

    private char[] increment(char[] password, int index) {
        if (password.length <= index) {
            password = Arrays.copyOf(password, password.length + 1);
            password[password.length - 1] = this.charset[0];
        }

        if (password[index] == this.charset[this.charset.length - 1]) {
            password[index] = this.charset[0];
            return increment(password, index + 1);
        } else {
            password[index] = this.charset[Chars.indexOf(this.charset, password[index]) + 1];
            return password;
        }
    }

    private static String bruteForcePassword(String salt, String hash, String charset, long pwMaxLength) {
        return new SimplePasswordCracker(salt, hash, charset).run(pwMaxLength);
    }
}
