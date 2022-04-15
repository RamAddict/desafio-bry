package br.com.bry.bianco.desafio;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

		// source file
		final var docToHash = "src/main/resources/doc.txt";
		// get hash of file
		final var hashAsEncodedString = new String(Hex.encode(getSha256Hash(docToHash)));
		// write to file
		try {
			FileUtils.write(FileUtils.getFile(docToHash.replace("doc.txt", "doc_hash.txt")), hashAsEncodedString, StandardCharsets.UTF_8);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	// @GetMapping
	// public String hello() {
	// 	return "henlo";
	// }

	private static byte[] getSha256Hash(String path) {

		// add new provider
		var bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
		
		MessageDigest digest = null;
		try {
			// make sure the provider is BC as per requirement, it would pick SUN otherwise
			digest = MessageDigest.getInstance("SHA-256", bcProvider.getName());
			
			// System.out.println(sha256.getProvider());
			// var sha256SUN = MessageDigest.getInstance("SHA-256"); 
			// System.out.println(sha256SUN.getProvider());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException  e) {
			e.printStackTrace();
		}
		
		// read file
		final var file = FileUtils.getFile(path);

		try {
			final var bytes = FileUtils.readFileToByteArray(file);
			return digest.digest(bytes);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

}
