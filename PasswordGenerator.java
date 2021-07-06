package com.chris.regex.password;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Collectors;
import java.io.*;

public class PasswordGenerator {
    private static final String CHAR_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String CHAR_UPPERCASE = CHAR_LOWERCASE.toUpperCase();
    private static final String DIGIT = "0123456789";
    private static final String PUNCTUATION = "!@#$%()-[{}]:;',?/*";
    private static final String SYMBOL = "~$^+=<>";
    private static final String PUNCT_SYMBOL_COMBO = PUNCTUATION + SYMBOL;
    private static final int PASSWORD_LENGTH = 20;

    private static final String getUserName(String prompt) {
        String username = null;
        System.out.print(prompt);
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        try {
            username = br.readLine();
        }
        catch (IOException e) {
            System.out.println("Error Trying to read username");
            System.exit(1);
        }
        return username;
    }

    private static final String PASSWORD_ALLOW =
            CHAR_LOWERCASE + CHAR_UPPERCASE + DIGIT + PUNCT_SYMBOL_COMBO;

    private static SecureRandom random = new SecureRandom();

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // Prompt for a username
        String username = getUserName("Username: ");

        // Now Generate a Password
        for (int i = 0; i < 1; i++) {
            generateStrongPassword();
        }

        // Now hash the PW that was just generated
        String passwordToHash = generateStrongPassword();
        byte[] salt = getSalt();
        String securePassword = get_SHA_512_SecurePassword(passwordToHash, salt);

        // Output the UN/PW/Hash on separate lines
        String userName = "Username:" + " " + username;
        String passWord = "Password:" + " " + generateStrongPassword();
        String hash = "Hash:" + " " + securePassword;
            System.out.println("The new credentials are:");
            System.out.println(userName);
            System.out.println(passWord);
            System.out.println(hash);

        // Turn the output into an insert statement for a DB
        System.out.println("SQL insert statement:");
        System.out.println("insert into <table> (Username, Password, Enabled)");
        System.out.println("values" + " " + "(" + "'" + username + "'" + "," + " " + "'" + securePassword + "'" + " " + "'" + "1" + "'" + ")" + ";");
    }

    public static String generateStrongPassword() {

        StringBuilder result = new StringBuilder(PASSWORD_LENGTH);

        //Get at least two lower case chars
        String strLowerCase = generateRandomString(CHAR_LOWERCASE, 2);
        //System.out.format("%-20s: %s%n", "Chars (Lowercase)", strLowerCase);
        result.append(strLowerCase);

        //Get at least two upper case chars
        String strUpperCase = generateRandomString(CHAR_UPPERCASE,  2);
        //System.out.format("%-20s: %s%n", "Chars (Uppercase)", strUpperCase);
        result.append(strUpperCase);

        //Get at least two digits
        String strDigit = generateRandomString(DIGIT, 2);
        //System.out.format("%-20s: %s%n", "Digits", strDigit);
        result.append(strDigit);

        //Get at least two special characters (puct + symbols)
        String strSpecialChar = generateRandomString(PUNCT_SYMBOL_COMBO, 2);
       // System.out.format("%-20s: %s%n", "Special chars", strSpecialChar);
        result.append(strSpecialChar);

        //Now generate chars at random
        String strOther = generateRandomString(PASSWORD_ALLOW, PASSWORD_LENGTH - 8);
        //System.out.format("%-20s: %s%n", "Others", strOther);
        result.append(strOther);

        String password = result.toString();
        //combine everything together
        return password;
    }

        //generate a random char[], based on `input`
        private static String generateRandomString(String input, int size) {

            if (input == null || input.length() <= 0)
                throw new IllegalArgumentException("Input is not valid.");
            if (size < 1) throw new IllegalArgumentException("Size is not Valid.");

            StringBuilder result = new StringBuilder(size);
            for (int i = 0; i < size; i++) {
                //Generate in random order
                int index = random.nextInt(input.length());
                result.append(input.charAt(index));
            }
            return result.toString();

        }

        //For the final password, make the pw more randomized:
        public static String shuffleString(String input) {
            List<String> result = Arrays.asList(input.split(""));
            Collections.shuffle(result);
            // for Java 8
            return result.stream().collect(Collectors.joining());

    }
        private static String get_SHA_512_SecurePassword(String passwordToHash, byte[] salt) {

            String generatedPassword = null;
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                md.update(salt);
                byte[] bytes = md.digest(passwordToHash.getBytes());
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < bytes.length; i++) {
                    sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
                }
                generatedPassword = sb.toString();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return generatedPassword;
        }
        //add salt
        private static byte[] getSalt() throws NoSuchAlgorithmException {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[16];
            sr.nextBytes(salt);
            return salt;
            }
}