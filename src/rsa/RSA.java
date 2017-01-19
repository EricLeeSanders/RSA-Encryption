package rsa;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * An RSA Encryption/Decryption program. Users can create public and private
 * keys and encrypt/decrypt messages.
 * 
 * Does not handle error exceptions and does not fail gracefully.
 * 
 * 
 * I let the variable names be the same as those used by Thomas Barr in his
 * book. Unfortunately, they aren't too descriptive.
 * 
 * @author Eric
 * 
 */
public class RSA {
	private static SecureRandom r = new SecureRandom();

	/**
	 * Creates a private and public key.
	 * 
	 * @param numOfDigits
	 * @param pubFileName
	 * @param privFileName
	 * @throws IOException
	 */
	public static void createKeys(int numOfDigits, String pubFileName,
			String privFileName) throws IOException {

		System.out.println("Generating primes and creating keys...");
		// Number of digits has to be greater than 1
		if(numOfDigits <= 1){
			numOfDigits = 2;
		}
		int bitLength = (int) (numOfDigits * (Math.log(10) / Math.log(2)));

		// calculate p and q
		BigInteger p = new BigInteger(bitLength, 1, r);
		BigInteger q = new BigInteger(bitLength, 1, r);
		while (p.equals(q)) {
			q = new BigInteger(bitLength, 1, r);
		}
		System.out.println("p = " + p);
		System.out.println("q = " + q);

		// calculate n (modulus)
		BigInteger n = p.multiply(q);
		System.out.println("n = " + n);

		// calculate phi
		BigInteger pMin1 = p.subtract(BigInteger.ONE);// Q minus 1
		BigInteger qMin1 = q.subtract(BigInteger.ONE);// P minus 1
		BigInteger phi = pMin1.multiply(qMin1);
		System.out.println("phi = " + phi);

		// create keys
		BigInteger e = createPublicKey(n, phi, bitLength, pubFileName);
		System.out.println("e = " + e);
		BigInteger d = createPrivateKey(p, q, n, e, phi, privFileName);
		System.out.println("d = " + d);
	}

	/**
	 * Creates a public key
	 * 
	 * @param n
	 * @param phi
	 * @param bitLength
	 * @param pubFileName
	 * @return BigInteger - e
	 * @throws IOException
	 */
	private static BigInteger createPublicKey(BigInteger n, BigInteger phi,
			int bitLength, String pubFileName) throws IOException {

		System.out.println("Creating public key and saving to: " + pubFileName);
		// calculates the public key, must be relatively prime to phi
		BigInteger e = new BigInteger(bitLength, 1, r);

		// Test if GCD = 1
		while (e.gcd(phi).compareTo(BigInteger.ONE) != 0) {
			e = new BigInteger(bitLength, 1, r);
		}

		saveKey(new PublicKey(n, e), pubFileName);
		return e;
	}

	/**
	 * Creates a private key
	 * 
	 * @param p
	 * @param q
	 * @param n
	 * @param e
	 * @param phi
	 * @param privFileName
	 * @return BigInteger - d
	 * @throws IOException
	 */
	private static BigInteger createPrivateKey(BigInteger p, BigInteger q,
			BigInteger n, BigInteger e, BigInteger phi, String privFileName)
			throws IOException {

		System.out.println("Creating private key and saving to: "
				+ privFileName);
		BigInteger d = e.modInverse(phi);
		saveKey(new PrivateKey(n, d, p, q), privFileName);
		return d;
	}

	/**
	 * Encrypts the text. If the text is >= modulus, the text needs to be split
	 * into blocks and encrypted separately.
	 * 
	 * @param plainText
	 * @param pubKey
	 * @return
	 */
	public static List<BigInteger> encrypt(String plainText, PublicKey pubKey) {

		System.out.println("Encrypting... plain text: " + plainText);

		BigInteger n = pubKey.getN();
		BigInteger e = pubKey.getE();

		List<String> plainTextInBlocks = splitTextIntoBlocks(plainText, n);
		List<BigInteger> cipherTextInBlocks = new ArrayList<BigInteger>();

		for (String textBlock : plainTextInBlocks) {
			BigInteger text = new BigInteger(textBlock, 36);
			BigInteger c = text.modPow(e, n);
			cipherTextInBlocks.add(c);
		}

		return cipherTextInBlocks;

	}

	/**
	 * Calculates and returns the block size for splitting the plain text when
	 * the text >= modulus.
	 * 
	 * @param n
	 * @return
	 */
	private static int getBlockSize(BigInteger n) {

		// Subtract 1 from bit length to ensure text block < modulus
		int nBitLength = n.bitLength() - 1;
		double alphaNumericBitLength = Math.ceil(Math.log(36) / Math.log(2));
		return (int) Math.floor(nBitLength / alphaNumericBitLength);
	}

	/**
	 * Splits the text into blocks based on the block size
	 * 
	 * @param plainText
	 * @param n
	 * @return
	 */
	private static List<String> splitTextIntoBlocks(String plainText,
			BigInteger n) {

		List<String> plainTextInBlocks = new ArrayList<String>();
		int blockSize = getBlockSize(n);

		// block size must be > 0
		blockSize = blockSize > 0 ? blockSize : 1;

		System.out.println("Splitting text into blocks with a block size = "
				+ blockSize);

		for (int i = 0; i < plainText.length(); i += blockSize) {
			int end = i + blockSize;
			end = end > plainText.length() ? plainText.length() : end;

			String blockedText = plainText.substring(i, end);
			plainTextInBlocks.add(blockedText);
		}

		System.out.println("Blocked Text: " + plainTextInBlocks);

		return plainTextInBlocks;
	}

	/**
	 * Decrypt the encrypted Text
	 * 
	 * @param c
	 * @param privKey
	 * @return
	 */
	public static BigInteger decrypt(BigInteger c, PrivateKey privKey) {

		BigInteger d = privKey.getD();
		BigInteger n = privKey.getN();
		BigInteger text = c.modPow(d, n);
		return text;

	}

	/**
	 * Save the encrypted text
	 * 
	 * @param cipherTextInBlocks
	 * @param saveCipherFile
	 * @throws IOException
	 */
	private static void saveCipherText(List<BigInteger> cipherTextInBlocks,
			String saveCipherFile) throws IOException {

		PrintWriter out = new PrintWriter(saveCipherFile);

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < cipherTextInBlocks.size(); i++) {
			sb.append(cipherTextInBlocks.get(i));

			if (i + 1 < cipherTextInBlocks.size()) {
				sb.append("\n");
			}
		}
		out.println(sb.toString());
		out.close();
	}

	/**
	 * Loads plain text from a file
	 * 
	 * @param plainTextFileName
	 * @return
	 * @throws FileNotFoundException
	 */
	private static String loadPlainText(String plainTextFileName)
			throws FileNotFoundException {

		Scanner fileIn = new Scanner(new FileReader(plainTextFileName));
		String plainText = fileIn.nextLine();
		fileIn.close();

		plainText = plainText.toUpperCase();
		plainText = plainText.replaceAll("[^a-zA-Z]", "");

		return plainText;
	}

	/**
	 * Saves cipher text to a file
	 * 
	 * @param cipherTextFileName
	 * @return
	 * @throws FileNotFoundException
	 */
	private static List<String> loadCipherText(String cipherTextFileName)
			throws FileNotFoundException {

		List<String> cipherText = new ArrayList<String>();

		Scanner fileIn = new Scanner(new FileReader(cipherTextFileName));

		while (fileIn.hasNextLine()) {
			String text = fileIn.nextLine();
			System.out.println( "text: " + text);
			cipherText.add(text);
		}

		fileIn.close();

		return cipherText;
	}

	/**
	 * Saves a key
	 * 
	 * @param key
	 * @param fileName
	 * @throws IOException
	 */
	private static void saveKey(Serializable key, String fileName)
			throws IOException {

		FileOutputStream fileOut = new FileOutputStream(fileName);
		ObjectOutputStream out = new ObjectOutputStream(fileOut);
		out.writeObject(key);
		out.close();
		fileOut.close();
	}

	/**
	 * Loads a key
	 * 
	 * @param keyName
	 * @return
	 * @throws IOException
	 */
	private static Object loadKey(String keyName) throws IOException {

		FileInputStream fileIn = new FileInputStream(keyName);
		ObjectInputStream in = new ObjectInputStream(fileIn);
		Object key = null;
		try {
			key = in.readObject();
		} catch (Exception e) {
			e.printStackTrace();
		}
		in.close();
		fileIn.close();

		return key;
	}

	public static void main(String[] args) throws IOException {

		Scanner in = new Scanner(System.in);
		PrivateKey loadedPrivKey = null;
		PublicKey loadedPubKey = null;
		boolean quit = false;

		while (!quit) {
			System.out.println();
			System.out.println("1) Create Private/Public Key \n"
					+ "2) Load a Private Key \n"
					+ "3) Load a Public Key \n"
					+ "4) Encrypt \n"
					+ "5) Decrypt \n"
					+ "6) Run Test Cases \n"
					+ "7) Quit");
			System.out.print("Enter a number from the menu: ");
			int i = in.nextInt();
			System.out.println();
			// Create keys
			if (i == 1) {
				System.out
						.println("How many digits should the prime numbers be?: ");
				int numOfDigits = in.nextInt();
				System.out
						.println("What do you want to name the public key file?:  ");
				String pubFileName = in.next();
				System.out
						.println("What do you want to name the private key file?:  ");
				String privFileName = in.next();
				RSA.createKeys(numOfDigits, pubFileName, privFileName);
			}
			// Load private key
			if (i == 2) {
				System.out
						.println("What is the name of the private key file?: ");
				String privFileName = in.next();
				loadedPrivKey = (PrivateKey) RSA.loadKey(privFileName);
			}
			// Load public key
			if (i == 3) {
				System.out.println("What is the name of public key file?: ");
				String pubFileName = in.next();
				loadedPubKey = (PublicKey) RSA.loadKey(pubFileName);
			}
			// Encrypt
			if (i == 4) {
				if (loadedPrivKey == null || loadedPubKey == null) {
					System.out.println("Public or Private Key not loaded");
					continue;
				}

				System.out
						.println("What is the name of the file to be encrypted?: ");
				String plainTextFileName = in.next();
				String plainText = RSA.loadPlainText(plainTextFileName);

				List<BigInteger> cipherText = RSA.encrypt(plainText,
						loadedPubKey);
				System.out.println("Cipher text = " + cipherText);
				System.out
						.println("What do you want to name the encrypted file?: ");

				String cipherTextFileName = in.next();
				RSA.saveCipherText(cipherText, cipherTextFileName);

			}
			// Decrypt
			if (i == 5) {
				if (loadedPrivKey == null || loadedPubKey == null) {
					System.out.println("Public or Private Key not loaded");
					continue;
				}

				System.out
						.println("What is the name of the file to be decrypted?: ");
				String cipherTextFileName = in.next();

				List<String> cipherTextList = RSA
						.loadCipherText(cipherTextFileName);
				System.out.println("Cipher text = " + cipherTextList);
				StringBuilder plainText = new StringBuilder();

				for (String cipherText : cipherTextList) {
					BigInteger c = new BigInteger(cipherText);
					BigInteger m = RSA.decrypt(c, loadedPrivKey);
					plainText.append(m.toString(36));
				}

				System.out.println("Decrypted Message = "
						+ plainText.toString());
			}
			if (i == 6) {
				
				String pubFileName = "test_pub.key";
				String privFileName = "test_priv.key";
				boolean testsFailed = false;
				
				System.out
						.println("How many tests cases do you want to run?: ");
				int numOfTestCases = in.nextInt();
				
				for (int j = 0; j < numOfTestCases; j++) {
					
					// Get random number of digits
					int rndNumOfDigits = r.nextInt(600) + 10;

					// create the keys
					RSA.createKeys(rndNumOfDigits, pubFileName, privFileName);
					loadedPrivKey = (PrivateKey) RSA.loadKey(privFileName);
					loadedPubKey = (PublicKey) RSA.loadKey(pubFileName);

					// Create some random plain text
					int rndBitLength = r.nextInt(4096) + 1;
					String rndPlainText = new BigInteger(rndBitLength, r)
							.toString(36);
					rndPlainText = rndPlainText.replaceAll("[^a-zA-Z]", "");

					// encrypt the plain text
					List<BigInteger> cipherTextInBlocks = RSA.encrypt(rndPlainText,
							loadedPubKey);
					StringBuilder plainText = new StringBuilder();

					// Decrypt the text
					for (BigInteger cipherTextBigInt : cipherTextInBlocks) {
						String cipherText = cipherTextBigInt.toString(36);
						BigInteger c = new BigInteger(cipherText, 36);
						BigInteger m = RSA.decrypt(c, loadedPrivKey);
						plainText.append(m.toString(36));
					}

					System.out.println("Decrypted: " + plainText.toString());

					if (!rndPlainText.equals(plainText.toString())) {
						System.out.println("Not equal!");
						testsFailed = true;
						break;
					}
				}
				
				if(testsFailed){
					System.out.println("Test case failed...");
				} else {
					System.out.println("All tests succeeded...");
				}

			}
			if (i == 7) {
				quit = true;
			}

		}
		in.close();
	}
}
