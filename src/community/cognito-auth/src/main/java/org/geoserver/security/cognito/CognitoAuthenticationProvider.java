package org.geoserver.security.cognito;

import com.thoughtworks.xstream.XStream;
import java.util.logging.Logger;
import org.geoserver.config.util.XStreamPersister;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.filter.AbstractFilterProvider;
import org.geoserver.security.filter.GeoServerSecurityFilter;
import org.geotools.util.logging.Logging;
import org.springframework.beans.factory.annotation.Autowired;

public class CognitoAuthenticationProvider extends AbstractFilterProvider {

    private static final Logger LOG = Logging.getLogger(CognitoAuthenticationProvider.class);

    @Autowired
    public CognitoAuthenticationProvider() {}

    @Override
    public void configure(XStreamPersister xp) {
        super.configure(xp);
        XStream xs = xp.getXStream();
        xs.allowTypes(new Class[] {CognitoAuthenticationFilterConfig.class});
        xs.alias("cognitoAuthentication", CognitoAuthenticationFilterConfig.class);
    }

    @Override
    public Class<? extends GeoServerSecurityFilter> getFilterClass() {
        return CognitoAuthenticationFilter.class;
    }

    @Override
    public GeoServerSecurityFilter createFilter(SecurityNamedServiceConfig config) {
        return new CognitoAuthenticationFilter();
    }

    //    @Override
    //    public SecurityConfigValidator createConfigurationValidator(
    //            GeoServerSecurityManager securityManager) {
    //        return new CognitoAuthenticationFilterConfigValidator(securityManager);
    //    }
}
