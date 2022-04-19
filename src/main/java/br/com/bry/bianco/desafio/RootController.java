package br.com.bry.bianco.desafio;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import lombok.extern.log4j.Log4j2;

@Log4j2
@RestController
public class RootController {
	@SuppressWarnings("rawtypes")
	@RequestMapping(path = "/signature", method = RequestMethod.POST, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity requestDocSignature(@RequestParam("toSign") MultipartFile toSign,
			@RequestParam("pkcsFile") MultipartFile pkcsFile,
			@RequestParam("password") String password) throws JsonProcessingException {

		try {
			var res = DesafioApplication.signDoc(toSign.getInputStream(), pkcsFile.getInputStream(),
					password.toCharArray(),
					"", "f22c0321-1a9a-4877-9295-73092bb9aa94");
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(res);
		} catch (Exception e) {
			log.error(e);
			var mapper = new ObjectMapper();
			var errorResponse = mapper.createObjectNode();
			errorResponse.put("error", e.getMessage());
			return ResponseEntity
					.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(errorResponse));
		}
	}

	@SuppressWarnings("rawtypes")
	@RequestMapping(path = "/verify", method = RequestMethod.POST, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity verifySignature(@RequestParam("signedMessage") MultipartFile signedMessage)
			throws JsonProcessingException {
		try {
			var res = DesafioApplication.verifyDoc(signedMessage.getInputStream()) ? "VALIDO" : "INVALIDO";
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(res);
		} catch (Exception e) {
			log.error(e);
			var mapper = new ObjectMapper();
			var errorResponse = mapper.createObjectNode();
			errorResponse.put("error", e.getMessage());
			return ResponseEntity
					.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(errorResponse));
		}
	}
}
