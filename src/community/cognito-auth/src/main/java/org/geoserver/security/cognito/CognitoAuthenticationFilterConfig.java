package org.geoserver.security.cognito;

import org.geoserver.security.config.SecurityAuthFilterConfig;
import org.geoserver.security.config.SecurityFilterConfig;

public class CognitoAuthenticationFilterConfig extends SecurityFilterConfig
        implements SecurityAuthFilterConfig {

    private String awsRegion;
    private String userPoolID;
    private String clientID;
    private String jwksFilePath;

    private static final long serialVersionUID = 1L;

    public String getAwsRegion() {
        return awsRegion;
    }

    public void setAwsRegion(String awsRegion) {
        this.awsRegion = awsRegion;
    }

    public String getUserPoolID() {
        return userPoolID;
    }

    public void setUserPoolID(String userPoolID) {
        this.userPoolID = userPoolID;
    }

    public String getClientID() {
        return clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    public String getJwksFilePath() {
        return jwksFilePath;
    }

    public void setJwksFilePath(String jwksFilePath) {
        this.jwksFilePath = jwksFilePath;
    }
}
