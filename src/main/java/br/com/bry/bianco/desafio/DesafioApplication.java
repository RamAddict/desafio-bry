package br.com.bry.bianco.desafio;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
// import org.springframework.web.bind.annotation.GetMapping;
// import org.springframework.web.bind.annotation.RestController;

import lombok.extern.log4j.Log4j2;

@Log4j2
@SpringBootApplication
// @RestController
public class DesafioApplication {

	public static void main(String[] args) {
		SpringApplication.run(DesafioApplication.class, args);
		log.info("begin");

		final var doc = "arquivos/doc.txt";
		// Add new provider "BC"
		addBouncyCastleAsProvider();

		try {
			// calculate hash of doc.txt
			hashDocument(doc);
			// sign doc with the given certificate
			signDoc(doc);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| OperatorCreationException | IOException | CMSException | NoSuchProviderException e) {
			e.printStackTrace();
		}
	}

	// @GetMapping
	// public String hello() {
	// return "henlo";
	// }

	private static void addBouncyCastleAsProvider() {
		var bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
	}

	private static void signDoc(String file) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, UnrecoverableKeyException, OperatorCreationException, CertificateEncodingException,
			CMSException {
		// get appropriate KeyStore instance
		final var ks = KeyStore.getInstance("PKCS12");

		// get the certificate
		final var password = "123456789".toCharArray();
		try (final var inputStream = DesafioApplication.class.getClassLoader()
				.getResourceAsStream("pkcs12/Desafio Estagio Java.p12")) {
			// add digital signature to keystore
			ks.load(inputStream, password);
		}
		// extract private key
		final var privKey = (PrivateKey) ks.getKey("f22c0321-1a9a-4877-9295-73092bb9aa94", password);

		CMSProcessableByteArray cmsData;
		// read file to sign
		try (final var inputStream = DesafioApplication.class.getClassLoader().getResourceAsStream(file)) {
			cmsData = new CMSProcessableByteArray(IOUtils.toByteArray(inputStream));
		}

		// generate digital signature
		final var gen = new CMSSignedDataGenerator();

		final var sha256Signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC")
				.build(privKey);
		gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
				.build(sha256Signer, (X509Certificate) ks.getCertificate("f22c0321-1a9a-4877-9295-73092bb9aa94")));

		// sign doc
		final var signedMessage = gen.generate(cmsData, true).getEncoded();

		// save as .p7s
		try (final var outputStream = FileUtils.openOutputStream(FileUtils.getFile("output/DesafioSigned.p7s"))) {
			IOUtils.write(signedMessage, outputStream);
		}

	}

	private static void hashDocument(final String docToHash)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		// make sure the provider is BC as per requirement, it would pick SUN otherwise
		final var digest = MessageDigest.getInstance("SHA-256", "BC");

		// read file
		try (final var file = DesafioApplication.class.getClassLoader().getResourceAsStream(docToHash)) {
			final var bytes = IOUtils.toByteArray(file);

			// perform hash
			final var hash = digest.digest(bytes);

			// get hexadecimal encoding
			final var hashAsEncodedString = new String(Hex.encode(hash));

			// write to file
			FileUtils.write(
					FileUtils.getFile("output",
							FilenameUtils.removeExtension(Path.of(docToHash).getFileName().toString())
									.concat("_hashed.txt")),
					hashAsEncodedString,
					StandardCharsets.UTF_8);
		}
	}

}
