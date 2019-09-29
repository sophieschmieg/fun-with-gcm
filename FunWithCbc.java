import java.nio.ByteBuffer;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class FunWithCbc {
  public static Charset UTF8 = Charset.forName("UTF-8");

  public static String encode(final byte[] bytes) {
    String chars = "0123456789abcdef";
    StringBuilder result = new StringBuilder(2 * bytes.length);
    for (byte b : bytes) {
      // convert to unsigned
      int val = b & 0xff;
      result.append(chars.charAt(val / 16));
      result.append(chars.charAt(val % 16));
    }
    return result.toString();
  }

  public static byte[] encrypt(byte message[], byte key[]) throws Exception {
    ByteBuffer in = ByteBuffer.wrap(message, 0, message.length);
    ByteBuffer out = ByteBuffer.allocate((message.length / 16 + 2) * 16);
    SecureRandom rand = new SecureRandom();
    byte iv[] = new byte[16];
    rand.nextBytes(iv);
    out.put(iv);
    IvParameterSpec s = new IvParameterSpec(iv);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), s);
    c.doFinal(in, out);
    return out.array();
  }

  public static byte[] decrypt(byte ciphertext[], byte key[]) throws Exception {
    ByteBuffer in = ByteBuffer.wrap(ciphertext, 0, ciphertext.length);
    byte iv[] = new byte[16];
    byte ciphertextWithoutIv[] = new byte[ciphertext.length - 16];
    in.get(iv);
    in.get(ciphertextWithoutIv);
    IvParameterSpec s = new IvParameterSpec(iv);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), s);
    return c.doFinal(ciphertextWithoutIv);
  }

  public static class Bob {
    private byte key[];
    private int guessCounter;

    public Bob(byte key[]) {
      this.key = key;
      this.guessCounter = 0;
    }
    
    public boolean oracle(byte ciphertext[]) {
      byte message[];
      this.guessCounter++;
      try {
        message = decrypt(ciphertext, key);
      } catch (Exception e) {
        return false;
      }
      return true;
    }

    public boolean guess(byte ciphertext[], byte plaintextGuess[]) {
      byte message[];
      try {
        message = decrypt(ciphertext, key);
      } catch (Exception e) {
        return false;
      }
      return Arrays.equals(message, plaintextGuess);
    }

    public int getGuessCounter() {
      return guessCounter;
    }

    public void printCBC(byte ciphertext[]) {
      try {
        byte trimmed[] = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte decrypted[] = c.doFinal(trimmed);
        for (int i = 0; i < decrypted.length; i++) {
          decrypted[i] = (byte)(ciphertext[i] ^ decrypted[i]);
        }
        System.out.println(encode(decrypted));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  public static class Alice {
    private byte key[];

    public Alice() {
      SecureRandom rand = new SecureRandom();
      key = new byte[32];
      rand.nextBytes(key);
    }

    byte[] getKey() {
      return key;
    }

    byte[] message(String plaintext) {
      byte ciphertext[];
      try {
        ciphertext = encrypt(plaintext.getBytes(UTF8), key);
      } catch (Exception e) {
        e.printStackTrace();
        return null;
      }
      return ciphertext;
    }
  }

  public static class Eve {
    private Bob bob;

    public Eve(Bob bob) {
      this.bob = bob;
    }

    public byte[] attack(byte ciphertext[]) {
      System.out.println("Eve: Trying to find the plaintext for:");
      System.out.println("  " + encode(ciphertext));
      System.out.println();
      System.out.println("This is what Bob sees with padding:");
      System.out.print("  ");
      bob.printCBC(ciphertext);
      byte padding = findPadding(ciphertext);
      byte plaintext[] = new byte[ciphertext.length - 16 - padding];
      for (int i = 0; i < plaintext.length; i++) {
        guessByte(plaintext.length - i - 1, ciphertext, plaintext);
      }
      return plaintext;
    }

    private void guessByte(int index, byte ciphertext[], byte plaintext[]) {
      byte padding = (byte)(ciphertext.length - plaintext.length - 16);
      byte ciphertextMod[] = Arrays.copyOf(ciphertext, (index / 16 + 2) * 16);
      byte newPadding = (byte)(ciphertextMod.length - index - 16);
      for (int i = ciphertextMod.length - 16 - 1; i > index; i--) {
        ciphertextMod[i] = (byte)(ciphertextMod[i] 
            ^ (i < plaintext.length ? 
              (plaintext[i] ^ newPadding) : (padding ^ newPadding)));
      }
      byte orig = ciphertextMod[index];
      System.out.println("Eve: Flipped bits for new padding 0x" + encode(new byte[] {newPadding}) + ":");
      System.out.print("  ");
      bob.printCBC(ciphertextMod);
      for (int guess = 0; guess < 256; guess++) {
        ciphertextMod[index] = (byte)(orig ^ newPadding ^ guess);
        if (bob.oracle(ciphertextMod)) {
          System.out.println("Found the valid padding, making the guess 0x" + encode(new byte[] {(byte)guess}) + ":");
          System.out.print("  ");
          bob.printCBC(ciphertextMod);
          plaintext[index] = (byte)guess;
          return;
        }
      }
      throw new RuntimeException("No guess found!");
    }

    private byte findPadding(byte ciphertext[]) {
      byte xor = 0x01;
      if (ciphertext.length % 16 != 0) {
        return (byte)0xff;
      }
      System.out.println("Eve: Looking for padding, modified ciphertext, now Bob sees:");
      for (byte padding = 0x01; padding <= 16; padding++) {
        if (padding + 16 >= ciphertext.length) {
          return 0x10;
        }
        byte modCiphertext[] = xorPlaintextByte(ciphertext.length - 16 - padding - 1, xor, ciphertext);
        System.out.print("  ");
        bob.printCBC(modCiphertext);
        if (bob.oracle(modCiphertext)) {
          return padding;
        }
      }
      return (byte)0xff;
    }

    
    private byte[] xorPlaintextByte(int index, byte xor, byte ciphertext[]) {
      if (ciphertext.length < index + 16) {
        throw new IndexOutOfBoundsException();
      }
      byte result[] = Arrays.copyOf(ciphertext, ciphertext.length);
      result[index] = (byte)(result[index] ^ xor);
      return result;
    }
  }

  public static void main(String[] args) {
    Alice alice = new Alice();
    Bob bob = new Bob(alice.getKey());
    Eve eve = new Eve(bob);
    String message = "";
    try {
      BufferedReader in = new BufferedReader(new InputStreamReader(System.in, UTF8));
      message = in.readLine();
    } catch (Exception e) {
      e.printStackTrace();
    }
    byte ciphertext[] = alice.message(message);
    byte guess[] = eve.attack(ciphertext);
    if (bob.guess(ciphertext, guess)) {
      System.out.println("Success: \"" + new String(guess, UTF8) + "\"");
      System.out.println("Number of guesses: " + bob.getGuessCounter());
    } else {
      System.out.println("Failed: \"" + encode(guess) + "\"");
    }
  }
}
