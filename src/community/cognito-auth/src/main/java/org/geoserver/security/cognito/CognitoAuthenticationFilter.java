package org.geoserver.security.cognito;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerRoleConverter;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.filter.GeoServerPreAuthenticationFilter;
import org.geoserver.security.impl.GeoServerRole;
import org.geotools.util.logging.Logging;

public class CognitoAuthenticationFilter extends GeoServerPreAuthenticationFilter {

    private static final Logger LOG = Logging.getLogger(CognitoAuthenticationFilter.class);

    private String clientID;
    private JWTVerifier jwtVerifier;

    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);

        CognitoAuthenticationFilterConfig authConfig = (CognitoAuthenticationFilterConfig) config;

        CognitoRSAKeyProvider keyProvider;
        if (authConfig.getJwksFilePath() != null && !authConfig.getJwksFilePath().isEmpty()) {
            keyProvider = new CognitoRSAKeyProvider(authConfig.getJwksFilePath());
        } else {
            keyProvider =
                    new CognitoRSAKeyProvider(
                            authConfig.getAwsRegion(), authConfig.getUserPoolID());
        }

        this.clientID = authConfig.getClientID();
        Algorithm algorithm = Algorithm.RSA256(keyProvider);

        this.jwtVerifier = JWT.require(algorithm).build();
    }

    private DecodedJWT decodeAndVerifyJWT(String token) {
        if (token != null) {
            token = token.replace("Bearer ", "");
            DecodedJWT jwt = jwtVerifier.verify(token);

            List<String> audience = jwt.getAudience();
            if (audience.stream().noneMatch(str -> str.equals(this.clientID))) {
                LOG.log(Level.WARNING, "JWT audience does not match Client ID");
                return null;
            }

            return jwt;
        } else {
            LOG.log(Level.WARNING, "No Authorization header");
            return null;
        }
    }

    @Override
    protected String getPreAuthenticatedPrincipal(HttpServletRequest request) {
        try {
            String token = request.getHeader("Authorization");
            DecodedJWT jwt = decodeAndVerifyJWT(token);

            if (jwt != null && !jwt.getClaim("cognito:username").isNull()) {
                return jwt.getClaim("cognito:username").asString();
            } else {
                return null;
            }
        } catch (Exception ex) {
            LOG.log(
                    Level.SEVERE,
                    "Error Retrieving Principal from Cognito Token: " + ex.getMessage());
            return null;
        }
    }

    @Override
    protected Collection<GeoServerRole> getRoles(HttpServletRequest request, String principal)
            throws IOException {

        Collection<GeoServerRole> roles = new ArrayList<GeoServerRole>();
        GeoServerRoleConverter converter = GeoServerExtensions.bean(GeoServerRoleConverter.class);

        String token = request.getHeader("Authorization");
        DecodedJWT jwt = decodeAndVerifyJWT(token);

        if (jwt != null && !jwt.getClaim("cognito:groups").isNull()) {
            List<String> groupList = jwt.getClaim("cognito:groups").asList(String.class);
            String groups = String.join(";", groupList);
            roles.addAll(converter.convertRolesFromString(groups, principal));
        }

        return roles;
    }

    @Override
    public String getCacheKey(HttpServletRequest request) {

        // Is caching required with everything in the header?
        // return super.getCacheKey(request);
        return null;
    }
}
