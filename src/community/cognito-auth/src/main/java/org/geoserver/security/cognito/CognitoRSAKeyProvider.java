package org.geoserver.security.cognito;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Logger;
import org.geotools.util.logging.Logging;

public class CognitoRSAKeyProvider implements RSAKeyProvider {

    private static final Logger LOG = Logging.getLogger(CognitoRSAKeyProvider.class);

    private final URL cognitoUrl;
    private final JwkProvider provider;

    public CognitoRSAKeyProvider(String awsRegion, String userPoolId) {
        try {
            String cognitoUrl =
                    "https://cognito-idp."
                            + awsRegion
                            + ".amazonaws.com/"
                            + userPoolId
                            + "/.well-known/jwks.json";
            this.cognitoUrl = new URL(cognitoUrl);
            provider = new JwkProviderBuilder(this.cognitoUrl).build();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public CognitoRSAKeyProvider(String jwksFilePath) {
        try {
            this.cognitoUrl = new File(jwksFilePath).toURI().toURL();
            provider = new JwkProviderBuilder(this.cognitoUrl).build();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public RSAPublicKey getPublicKeyById(String keyId) {
        try {
            Jwk jwk = provider.get(keyId);
            return (RSAPublicKey) jwk.getPublicKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return null;
    }

    @Override
    public String getPrivateKeyId() {
        return null;
    }
}
