import java.nio.ByteBuffer;
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

class FunWithGcm {
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
    ByteBuffer out = ByteBuffer.allocate(message.length + 16 + 12);
    SecureRandom rand = new SecureRandom();
    byte iv[] = new byte[12];
    rand.nextBytes(iv);
    out.put(iv);
    GCMParameterSpec s = new GCMParameterSpec(128, iv);
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), s);
    c.updateAAD(new byte[0]);
    c.doFinal(in, out);
    return out.array();
  }

  public static byte[] decrypt(byte ciphertext[], byte key[]) throws Exception {
    ByteBuffer in = ByteBuffer.wrap(ciphertext, 0, ciphertext.length);
    ByteBuffer out = ByteBuffer.allocate(ciphertext.length - 16 - 12);
    byte iv[] = new byte[12];
    in.get(iv);
    GCMParameterSpec s = new GCMParameterSpec(128, iv);
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), s);
    c.doFinal(in, out);
    return out.array();
  }

  public static boolean trent(byte ciphertext[], byte key[]) throws Exception {
    byte message[];
    System.in.read();
    System.out.println("Trent: I've received the encrypted message \"" + encode(Arrays.copyOf(ciphertext, 4)) + "...\" from Alice,");
    System.out.print("       and the key \"" + encode(Arrays.copyOf(key, 4)) + "...\"");
    System.in.read();
    try {
      System.out.print("Trent: I will decrypt this and scan for evil messages.");
      message = decrypt(ciphertext, key);
      System.in.read();
    } catch (Exception e) {  // Message did not decrypt.
      System.out.print("  Decryption failed!");
      System.in.read();
      System.out.print("Trent: Gotcha, evildoer: Invalid ciphertext!");
      return false;
    }
    System.out.println("  Decryption successful.");
    System.out.print("  Message is \"" + encode(message) + "\".");
    System.in.read();
    if (message[0] == 0x13 && message[1] == 0x37) {
      System.out.print("  Evil Message!");
      System.in.read();
      System.out.print("Trent: Gotcha, evildoer: Evil message!");
      return false;
    }
    System.out.print("Trent: Everything is perfect, no evil detected!");
    return true;
  }

  public static void bob(byte ciphertext[], byte key[]) throws Exception {
    byte message[];
    System.in.read();
    System.out.println("Bob: I've received the encrypted message \"" + encode(Arrays.copyOf(ciphertext, 4)) + "...\" from Trent, he says it's okay,");
    System.out.print("     and Alice gave me the key \"" + encode(Arrays.copyOf(key, 4)) + "...\"");
    System.in.read();
    try {
      System.out.print("Bob: Let's try to decrypt this.");
      System.in.read();
      message = decrypt(ciphertext, key);
    } catch (Exception e) {  // Decryption failed.
      System.out.print("  Decryption failed!");
      System.in.read();
      System.out.print("Bob: Yeah, that doesn't work?");
      System.in.read();
      System.out.print("Bob could not decrypt the message, Bob wins!");
      return;
    }
    System.out.println("  Decryption successful.");
    System.out.print("  Message is \"" + encode(message) + "\".");
    System.in.read();
    if (message[0] == 0x13 && message[1] == 0x37) {
      System.out.print("  Evil Message!");
      System.in.read();
      System.out.print("Bob: OH NO!");
      System.in.read();
      System.out.print("Alice managed to sneak an evil message to Bob, Alice wins!");
      return;
    }
    System.out.print("Bob: Interesting message!");
    System.in.read();
    System.out.print("Bob got a good message, Bob wins!");
  }

  public static void aliceOutput(byte ciphertext[], byte keyForTrent[], byte keyForBob[]) throws Exception {
    if (trent(ciphertext, keyForTrent)) {
      bob(ciphertext, keyForBob);
    } else {
      System.in.read();
      System.out.print("Trent cannot guarantee that the message is good, Bob wins!");
    }
    System.in.read();
  }

  public static byte[] gctr(byte message[], byte iv[], byte key[]) throws Exception {
    return gctr(message, iv, key, 2);
  }

  public static byte[] gctr(byte message[], byte iv[], byte key[], int offset) throws Exception {
    ByteBuffer messageBlock = ByteBuffer.allocate(16);
    ByteBuffer encrypted = ByteBuffer.allocate(message.length);
    for (int i = 0; i < (message.length - 1)/ 16 + 1; i++) {
      int leftover = Math.min(message.length - i * 16, 16);
      messageBlock.put(message, i * 16, leftover);
      messageBlock.put(new byte[16 - leftover]);
      encrypted.put(gctrBlock(messageBlock.array(), iv, key, i + offset), 0, leftover);
      messageBlock.rewind();
    }
    return encrypted.array();
  }

  public static byte[] gctrBlock(byte block[], byte iv[], byte key[], int offset) throws Exception {
    ByteBuffer ivp = ByteBuffer.allocate(16);
    ivp.put(iv);
    ivp.putInt(offset);
    Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
    return add(c.doFinal(ivp.array()), block);
  }

  public static byte[] authKey(byte key[]) throws Exception {
    return gctr(new byte[16], new byte[12], key, 0);
  }

  public static byte[] tagBlock(byte iv[], byte key[]) throws Exception {
    return gctr(new byte[16], iv, key, 1);
  }

  public static byte[] gctrBlock(byte iv[], byte key[], int block) throws Exception {
    return gctr(new byte[16], iv, key, block);
  }

  public static byte[] add(byte a[], byte b[]) throws Exception {
    if (a.length != 16 || b.length != 16) {
      throw new Exception("Block size wrong!");
    }
    byte res[] = new byte[16];
    for (int i = 0; i < 16; i++) {
      res[i] = (byte)(a[i] ^ b[i]);
    }
    return res;
  }

  public static int degree(byte in[]) throws Exception {
    if (in.length != 16) {
      throw new Exception("Block size wrong!");
    }
    for (int i = 0; i < 16; i++) {
      for (int j = 0; j < 8; j++) {
        int mask = 0x01 << j;
        if ((mask & in[15 - i]) == mask) {
	  return 8 * (15 - i) + 7 - j;
	}
      }
    }
    return -1;
  }

  public static byte[] powerOfX(int n) throws Exception {
    if (n < 0 || n >= 128) {
      throw new Exception("Wrong exponent size");
    }
    byte res[] = new byte[16];
    res[n / 8] = (byte)(0x01 << (7 - (n % 8)));
    return res;
  }

  public static byte[] inverse(byte[] a) throws Exception {
    if (a.length != 16) {
      throw new Exception("Block size wrong!");
    }
    int deg = degree(a);
    if (deg < 0) {
      throw new Exception("Division by zero!");
    }
    if (deg == 0) {
      return a;
    }
    a = Arrays.copyOf(a, 16);
    byte b[] = mul(Arrays.copyOf(a, 16), powerOfX(128 - deg));
    // p = X^128 + X^7 + X^2 + X + 1
    byte x[] = powerOfX(0);  // x(0) * a + 0 * p = a(0)
    byte y[] = powerOfX(128 - deg);  // y(0) * a + 1 * p = b(0)
    while (deg > 0) {
      int degb = degree(b);
      if (deg > degb) {
        byte tmp[] = a;
	a = b;
	b = tmp;
	tmp = x;
	x = y;
	y = tmp;
	int degtmp = deg;
	deg = degb;
	degb = degtmp;
      }
      b = add(mul(a, powerOfX(degb - deg)), b);  // b(n+1) = b(n) + X^(deg(b(n)) - deg(a(n))) * a(n)
      // x(n) * a + ? * p = a(n)
      // y(n) * a + ? * p = b(n)
      // b(n + 1) = y(n) * a + X^d * (x(n) * a)) = (y(n) + X^d * x(n)) * a
      // x(n + 1) = x(n)
      // y(n + 1) = y(n) + X^d * x(n)
      y = add(y, mul(x, powerOfX(degb - deg)));
    }
    return x;
  }

  public static byte rightShiftByteOne(byte in) {
    return (byte)((in >> 1) & 0x7f);
  }

  public static byte[] mulByX(byte a[]) throws Exception {
    if (a.length != 16) {
      throw new Exception("Block size wrong!");
    }
    byte res[] = new byte[16];
    for (int i = 1; i < 16; i++) {
      res[i] = (byte)(rightShiftByteOne(a[i]) | (a[i-1] << 7));
    }
    res[0] = (byte)(rightShiftByteOne(a[0]) ^ (((a[15] & 0x01) == 0x01) ? 0xe1: 0));
    return res;
  }

  public static byte[] mul(byte a[], byte b[]) throws Exception {
    if (a.length != 16 || b.length != 16) {
      throw new Exception("Block size wrong!");
    }
    byte res[] = new byte[16];
    byte mulX[] = Arrays.copyOf(a, 16);
    for (int i = 0; i < 16; i++) {
      for (int j = 0; j < 8; j++) {
        int mask = 0x01 << 7 - j;
        if ((mask & b[i]) == mask) {
	  res = add(res, mulX);
	}
	mulX = mulByX(mulX);
      }
    }
    return res;
  }

  public static byte[] lengthBlock(int aadLength, int ciphertextLength) {
    ByteBuffer lastBlock = ByteBuffer.allocate(16);
    lastBlock.putLong(aadLength * 8);
    lastBlock.putLong(ciphertextLength * 8);
    return lastBlock.array();
  }

  public static byte[] ghash(byte aad[], byte ciphertext[], byte authKey[]) throws Exception {
    byte block[];
    byte res[] = new byte[16];
    for (int i = 0; i < (aad.length + 15) / 16; i++) {
      block = Arrays.copyOfRange(aad, i*16, (i+1)*16);
      res = mul(add(res, block), authKey);
    }
    for (int i = 0; i < (ciphertext.length + 15) / 16; i++) {
      block = Arrays.copyOfRange(ciphertext, i*16, (i+1)*16);
      res = mul(add(res, block), authKey);
    }
    res = mul(add(res, lengthBlock(aad.length, ciphertext.length)), authKey);
    return res;
  }

  public static byte[] manualGCM(byte message[], byte iv[], byte key[]) throws Exception {
    ByteBuffer out = ByteBuffer.allocate(message.length + 12 + 16);
    out.put(iv);
    byte ciphertext[] = gctr(message, iv, key);
    out.put(ciphertext);
    byte tagBlock[] = tagBlock(iv, key);
    byte ghash[] = ghash(new byte[0], ciphertext, authKey(key));
    out.put(add(tagBlock, ghash));
    return out.array();
  }
  
  public static void main(String[] args) throws Exception {
    byte message[] = "Hello, World!".getBytes(Charset.forName("UTF-8"));
    SecureRandom rand = new SecureRandom();
    byte key[] = new byte[32];
    rand.nextBytes(key);
    byte key2[] = new byte[32];
    rand.nextBytes(key2);
    byte ciphertext[] = encrypt(message, key);
    System.out.println("---------------------------------------------------------------------------");
    System.out.println("Scenario 1: good message, Bob and Trent get the correct key.");
    System.out.print("---------------------------------------------------------------------------");
    aliceOutput(ciphertext, key, key);
    System.out.println();
    System.out.println("---------------------------------------------------------------------------");
    System.out.println("Scenario 2: good message, Trent gets the correct key, Bob gets a wrong key.");
    System.out.print("---------------------------------------------------------------------------");
    aliceOutput(ciphertext, key, key2);
    System.out.println();
    System.out.println("---------------------------------------------------------------------------");
    System.out.println("Scenario 3: good message, Trent gets a wrong key, Bob gets the correct key.");
    System.out.print("---------------------------------------------------------------------------");
    aliceOutput(ciphertext, key2, key);
    message[0] = 0x13;
    message[1] = 0x37;
    ciphertext = encrypt(message, key);
    System.out.println();
    System.out.println("---------------------------------------------------------------------------");
    System.out.println("Scenario 4: evil message, Bob and Trent get the correct key.");
    System.out.print("---------------------------------------------------------------------------");
    aliceOutput(ciphertext, key, key);

    byte message1[] = new byte[16];
    message1[0] = 0x13;
    message1[1] = 0x37;
    byte iv[] = new byte[12];
    rand.nextBytes(iv);
    byte authKey1[] = authKey(key);
    byte authKey2[] = authKey(key2);
    byte tagBlock1[] = tagBlock(iv, key);
    byte tagBlock2[] = tagBlock(iv, key2);
    byte ciphertext1[] = gctr(message1, iv, key);
    byte lengthBlock[] = lengthBlock(0, 32);
    // tag(H, tb) = c1 * H^3 + c2 * H^2 + lb * H + tb
    // c1 * H1^3 + c2 * H1^2 + lb * H1 + tb1 = c1 * H2^3 + c2 * H2^2 + lb * H2 + tb2
    // c2 * (H1^2 + H2^2) = c1 * (H1^3 + H2^3) + lb * (H1 + H2) + tb1 + tb2
    byte rhs[] = add(tagBlock1, tagBlock2);
    rhs = add(rhs, mul(lengthBlock, add(authKey1, authKey2)));
    byte authKey1sq[] = mul(authKey1, authKey1);
    byte authKey2sq[] = mul(authKey2, authKey2);
    byte lhs[] = add(authKey1sq, authKey2sq);
    byte authKey1cb[] = mul(authKey1sq, authKey1);
    byte authKey2cb[] = mul(authKey2sq, authKey2);
    rhs = add(rhs, mul(ciphertext1, add(authKey1cb, authKey2cb)));
    byte ciphertext2[] = mul(inverse(lhs), rhs);
    ByteBuffer attackCiphertext = ByteBuffer.allocate(32);
    attackCiphertext.put(ciphertext1);
    attackCiphertext.put(ciphertext2);
    byte ghash[] = ghash(new byte[0], attackCiphertext.array(), authKey1);
    ByteBuffer attack = ByteBuffer.allocate(12 + 32 + 16);
    attack.put(iv);
    attack.put(ciphertext1);
    attack.put(ciphertext2);
    attack.put(add(tagBlock1, ghash));
    ciphertext = attack.array();
    System.out.println();
    System.out.println("---------------------------------------------------------------------------");
    System.out.println("Scenario 5: Trent gets a good message with the correct key,");
    System.out.println("            Bob gets an evil message with the correct key.");
    System.out.print("---------------------------------------------------------------------------");
    aliceOutput(ciphertext, key2, key);
  }
}
