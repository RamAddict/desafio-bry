package br.com.bry.bianco.desafio;

import java.io.IOException;
import java.io.InputStream;
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
import java.util.Base64;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSVerifierCertificateNotValidException;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import lombok.extern.log4j.Log4j2;

@Log4j2
@SpringBootApplication
public class DesafioApplication {

	public static void main(String[] args) throws IOException {
		SpringApplication.run(DesafioApplication.class, args);
		log.info("begin");

		final var docToHash = "arquivos/doc.txt";
		try (
				final var docStream = DesafioApplication.class.getClassLoader().getResourceAsStream(docToHash);
				final var signatures = DesafioApplication.class.getClassLoader()
						.getResourceAsStream("pkcs12/Desafio Estagio Java.p12")) {

			final var password = "123456789".toCharArray();
			// Add new provider "BC"
			addBouncyCastleAsProvider();

			try {
				// calculate hash of doc.txt
				hashDoc(docToHash);
				// sign doc with the given certificate
				signDoc(docStream, signatures, password, "desafioSigned", "f22c0321-1a9a-4877-9295-73092bb9aa94");
				// verify signature
				try (final var signedDoc = FileUtils.openInputStream(FileUtils.getFile("output/desafioSigned.p7s"))) {
					verifyDoc(signedDoc);
				}

			} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
					| OperatorCreationException | IOException | CMSException | NoSuchProviderException e) {
				e.printStackTrace();
			}
		}
	}

	public static boolean verifyDoc(InputStream doc) throws OperatorCreationException, CMSException, IOException {
		// parse file
		final var signedParser = new CMSSignedDataParser(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), doc);

		// consume input stream, to allow for hash calculation
		signedParser.getSignedContent().drain();
		// get signers
		final var signers = signedParser.getSignerInfos();
		// and certificates
		final var certificates = signedParser.getCertificates();
		// verify
		final var isValid = signers.getSigners().stream().allMatch((signer) -> {
			@SuppressWarnings("unchecked")
			final var possibleCertificate = certificates.getMatches(signer.getSID()).stream().findFirst();
			if (possibleCertificate.isPresent()) {
				final var certificate = (X509CertificateHolder) possibleCertificate.get();
				try {
					final var jcaSignerVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
							.build(certificate);
					return signer.verify(jcaSignerVerifier);
				} catch (CMSVerifierCertificateNotValidException e) {
					log.info("Certificate expired!");
					return false;
				} catch (OperatorCreationException | CertificateException | CMSException e) {
					return false;
				}
			} else {
				return false;
			}
		});
		return isValid;
	}

	public static void addBouncyCastleAsProvider() {
		var bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
	}

	public static String signDoc(InputStream toSign, InputStream signers, char[] password, String outputFileName,
			String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, UnrecoverableKeyException, OperatorCreationException, CertificateEncodingException,
			CMSException {
		// get appropriate KeyStore instance
		final var ks = KeyStore.getInstance("PKCS12");

		// add digital signature to keystore
		ks.load(signers, password);

		// extract private key
		// TODO: This method will only look for and sign with the given alias, fix this
		// by using the known aliases ks.aliases()
		final var privKey = (PrivateKey) ks.getKey(alias, password);
		final var certificate = ks.getCertificate(alias);

		CMSProcessableByteArray cmsData;

		// read file to sign
		cmsData = new CMSProcessableByteArray(IOUtils.toByteArray(toSign));

		// generate digital signature
		final var gen = new CMSSignedDataGenerator();

		final var sha256Signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC")
				.build(privKey);
		gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
				.build(sha256Signer, (X509Certificate) certificate));
		gen.addCertificate(new X509CertificateHolder(certificate.getEncoded()));
		// sign doc
		final var signedMessage = gen.generate(cmsData, true).getEncoded();

		// save as .p7s
		if (outputFileName != "")
			try (final var outputStream = FileUtils
					.openOutputStream(FileUtils.getFile("output/" + outputFileName + ".p7s"))) {
				IOUtils.write(signedMessage, outputStream);
			}

		return Base64.getEncoder().encodeToString(signedMessage);
	}

	public static void hashDoc(final String docToHash)
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
