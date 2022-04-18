package br.com.bry.bianco.desafio;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class DesafioApplicationTests {

	@BeforeAll
	@Test
	static void testBouncyCastleAddedAsProvider() {
		// Fixture Setup
		// Exercise SUT
		assertDoesNotThrow(() -> {
			DesafioApplication.addBouncyCastleAsProvider();
		});
		// Result Verification
		assertNotEquals(null, Security.getProvider("BC"));
		// Fixture Teardown
	}

	@Test
	void testIsHashValid() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		// Fixture Setup

		// Exercise SUT
		assertDoesNotThrow(() -> {
			DesafioApplication.hashDoc("arquivos/test.txt");
		});
		// Result Verification
		final var outputFile = FileUtils.getFile("output/test_hashed.txt");

		final String hash = FileUtils.readFileToString(outputFile, StandardCharsets.UTF_8);

		assertEquals("eb201af5aaf0d60629d3d2a61e466cfc0fedb517add831ecac5235e1daa963d6", hash);
		// Fixture Teardown
		FileUtils.delete(outputFile);
	}

	@Test
	void testSignDocument() throws UnrecoverableKeyException, CertificateEncodingException, KeyStoreException,
	NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException, CMSException {
		// Fixture Setup
		
		final var toSign = this.getClass().getClassLoader().getResourceAsStream("arquivos/test.txt");
		final var signers = this.getClass().getClassLoader().getResourceAsStream("pkcs12/test_pkcs.p12");
		final var password = "12345".toCharArray();
		final var outputFileName = "testSignedWithTestCertificate_test";
		
		// Exercise SUT
		// Result Verification
		assertDoesNotThrow(() -> DesafioApplication.signDoc(toSign, signers, password, outputFileName, "test_alias"));
		
		// Fixture Teardown
	}
	@Nested
	class TestSignatureVerification {
		@Test
		void testVerifySignatureExpiredDocument()
		throws UnrecoverableKeyException, CertificateEncodingException, KeyStoreException,
		NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException, CMSException {
			// Fixture Setup
			
			final var signed = FileUtils.openInputStream(FileUtils.getFile("output/desafioSigned.p7s"));
			// Exercise SUT
			final var signature = DesafioApplication.verifyDoc(signed);
			// Result Verification
			assertFalse(signature);
			// Fixture Teardown
			signed.close();
		}
		
		@Test
		void testVerifySignatureNonExpiredDocument()
		throws UnrecoverableKeyException, CertificateEncodingException, KeyStoreException,
		NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException, CMSException {
			// Fixture Setup
			
			final var signed = FileUtils
			.openInputStream(FileUtils.getFile("output/testSignedWithTestCertificate_test.p7s"));
			// Exercise SUT
			final var signature = DesafioApplication.verifyDoc(signed);
			// Result Verification
			assertTrue(signature);
			// Fixture Teardown
			signed.close();
		}
	}
		
}
