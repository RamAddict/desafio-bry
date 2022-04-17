package br.com.bry.bianco.desafio;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class RootController {
    @RequestMapping(path = "/signature", method = RequestMethod.POST, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public String requestDocSignature(@RequestParam("toSign") MultipartFile toSign,
			@RequestParam("pkcsFile") MultipartFile pkcsFile,
			@RequestParam("password") String password)
			throws UnrecoverableKeyException, CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, OperatorCreationException, IOException, CMSException {

		return DesafioApplication.signDoc(toSign.getInputStream(), pkcsFile.getInputStream(), password.toCharArray(), false);
	}

	@RequestMapping(path = "/verify", method = RequestMethod.POST, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public String verifySignature(@RequestParam("signedMessage") MultipartFile signedMessage)
			throws UnrecoverableKeyException, CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, OperatorCreationException, IOException, CMSException {

		return DesafioApplication.verifyDoc(signedMessage.getInputStream()) ? "VALIDO" : "INVALIDO";
	}
}
