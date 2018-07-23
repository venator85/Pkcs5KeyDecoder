import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;

public class Pkcs5Decoder {

	private static final String PKCS5_BEGIN = "-----BEGIN RSA PRIVATE KEY-----\n";
	private static final String PKCS5_END = "-----END RSA PRIVATE KEY-----";

	public static void main(String[] args) throws Exception {
//		String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
//				"MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw\n" +
//				"33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW\n" +
//				"+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n" +
//				"AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS\n" +
//				"3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp\n" +
//				"uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE\n" +
//				"2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0\n" +
//				"GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K\n" +
//				"Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY\n" +
//				"6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5\n" +
//				"fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523\n" +
//				"Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP\n" +
//				"FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n" +
//				"-----END RSA PRIVATE KEY-----";
		String key = convertStreamToString(System.in);
		key = key.trim();

		if (!key.startsWith(PKCS5_BEGIN)) {
			throw new IllegalArgumentException("Key is not in PKCS#5 format: must begin with " + PKCS5_BEGIN.trim());
		}
		if (!key.endsWith(PKCS5_END)) {
			throw new IllegalArgumentException("Key is not in PKCS#5 format: must end with " + PKCS5_END);
		}

		String privKeyPEM = key
				.replace(PKCS5_BEGIN, "")
				.replace(PKCS5_END, "")
				.replace("\n", "");

		byte[] encodedPrivateKey = Base64.getDecoder().decode(privKeyPEM);

		ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence.fromByteArray(encodedPrivateKey);
		Enumeration<?> e = primitive.getObjects();

		BigInteger v = ((ASN1Integer) e.nextElement()).getValue();
		int version = v.intValue();
		if (version != 0 && version != 1) {
			throw new IllegalArgumentException("wrong version for RSA private key");
		}

		BigInteger modulus = ((ASN1Integer) e.nextElement()).getValue();
		System.out.println("modulus = " + modulus);
		BigInteger publicExponent = ((ASN1Integer) e.nextElement()).getValue();
		System.out.println("publicExponent = " + publicExponent);
		BigInteger privateExponent = ((ASN1Integer) e.nextElement()).getValue();
		System.out.println("privateExponent = " + privateExponent);

//		BigInteger prime1 = ((ASN1Integer) e.nextElement()).getValue();
//		BigInteger prime2 = ((ASN1Integer) e.nextElement()).getValue();
//		BigInteger exponent1 = ((ASN1Integer) e.nextElement()).getValue();
//		BigInteger exponent2 = ((ASN1Integer) e.nextElement()).getValue();
//		BigInteger coefficient = ((ASN1Integer) e.nextElement()).getValue();
	}

	private static String convertStreamToString(InputStream is) {
		Scanner s = new Scanner(is).useDelimiter("\\A");
		return s.hasNext() ? s.next() : "";
	}

}
