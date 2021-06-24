package me.secosme.auth0jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Date;
import java.time.LocalDate;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws IOException, URISyntaxException, NoSuchAlgorithmException, InvalidKeySpecException {

        // produce the public and private key

        String privateKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("private_key_pkcs8.pem").toURI())));
        String publicKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("public_key.pem").toURI())));

        privateKeyContent = privateKeyContent.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace("\n", "").replace("\r", "");
        publicKeyContent = publicKeyContent.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "").replace("\r", "");

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

        // generate JWT with the private key

        Algorithm algorithm = Algorithm.RSA256(null, (RSAPrivateKey) privateKey);

        String token = JWT.create()
            .withClaim("company", "001")
            .withClaim("dni", "9807645")
            .withClaim("name", "Sara Conor")
            .withExpiresAt(Date.valueOf(LocalDate.now().plusDays(1)))
            .sign(algorithm);

        System.out.printf("JWT RSA256: %s\n", token);

        // verify token with the public key

        JWTVerifier verifier = JWT.require(Algorithm.RSA256(publicKey, null))
            .build();

        DecodedJWT jwt = verifier.verify(token);

        System.out.printf("Company: %s\n", jwt.getClaim("company"));

    }

}
