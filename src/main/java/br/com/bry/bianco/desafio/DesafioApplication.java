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
import java.security.cert.Certificate;
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
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
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

	public static boolean verifyDoc(InputStream doc) throws OperatorCreationException, IOException, CMSException {
		// parse file
		CMSSignedDataParser signedParser = null;
		SignerInformationStore signers = null;
		@SuppressWarnings("rawtypes")
		Store certificates = null;
		try {
			signedParser = new CMSSignedDataParser(
					new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), doc);
			// consume input stream, to allow for hash calculation
			signedParser.getSignedContent().drain();
			// get signers
			signers = signedParser.getSignerInfos();
			// and certificates
			certificates = signedParser.getCertificates();
		} catch (CMSException e1) {
			log.error(e1);
			throw new CMSException("Arquivo parâmetro inválido", e1);
		}
		final var certificatesFinal = certificates;
		
		// verify
		final var isValid = signers.getSigners().stream().allMatch((signer) -> {
		@SuppressWarnings("unchecked")
		final var possibleCertificate = certificatesFinal.getMatches(signer.getSID()).stream().findFirst();
			if (possibleCertificate.isPresent()) {
				final var certificate = (X509CertificateHolder) possibleCertificate.get();
				try {
					final var jcaSignerVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
							.build(certificate);
					return signer.verify(jcaSignerVerifier);
				} catch (CMSVerifierCertificateNotValidException e) {
					log.error("Certificate invalid!");
					return false;
				} catch (OperatorCreationException | CertificateException | CMSException e) {
					log.error(e);
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
			throws NoSuchAlgorithmException, CertificateException,
			IOException, UnrecoverableKeyException, OperatorCreationException, CertificateEncodingException,
			CMSException, KeyStoreException {
		// get appropriate KeyStore instance
		final var ks = KeyStore.getInstance("PKCS12");

		// add digital signature to keystore
		try {
			ks.load(signers, password);
		} catch (IOException e) {
			log.error(e);
			throw new IOException("Senha incorreta ou arquivo mal formado", e);
		}

		// extract private key
		// TODO: This method will only look for and sign with the given alias, fix this
		// by using the known aliases ks.aliases(), however, this is beyond scope
		PrivateKey privKey;
		try {
			privKey = (PrivateKey) ks.getKey(alias, password);
		} catch (KeyStoreException e) {
			log.error(e);
			throw new KeyStoreException("Não foi possível encontrar a chave com o par de alias e senha recebido", e);
		}
		Certificate certificate;
		try {
			certificate = ks.getCertificate(alias);
		} catch (KeyStoreException e) {
			log.error(e);
			throw new KeyStoreException("Não foi possível encontrar o certificado com o alias recebido", e);
		}

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
		try {
			gen.addCertificate(new X509CertificateHolder(certificate.getEncoded()));
		} catch (CMSException e) {
			log.error(e);
			throw new CMSException("Erro ao realizar o encoding do arquivo", e);
		} catch (IOException e) {
			log.error(e);
			throw new IOException("Dados corrompidos ou estrutura inválido", e);
		}
		// sign doc
		byte[] signedMessage;
		try {
			signedMessage = gen.generate(cmsData, true).getEncoded();
		} catch (CMSException e) {
			log.error(e);
			throw new CMSException("Erro ao assinar o documento", e);
		}
		// save as .p7s
		if (outputFileName != "")
			try (final var outputStream = FileUtils
					.openOutputStream(FileUtils.getFile("output/" + outputFileName + ".p7s"))) {
				IOUtils.write(signedMessage, outputStream);
			} catch (IOException e) {
				log.error(e);
				throw new IOException("Erro ao escrever arquivo em sistema", e);
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
