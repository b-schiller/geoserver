package org.geoserver.web.security.cognito;

import org.geoserver.security.cognito.CognitoAuthenticationFilter;
import org.geoserver.security.cognito.CognitoAuthenticationFilterConfig;
import org.geoserver.security.web.auth.AuthenticationFilterPanelInfo;

public class CognitoAuthFilterPanelInfo
        extends AuthenticationFilterPanelInfo<
                CognitoAuthenticationFilterConfig, CognitoAuthFilterPanel> {

    private static final long serialVersionUID = 1L;

    public CognitoAuthFilterPanelInfo() {
        setComponentClass(CognitoAuthFilterPanel.class);
        setServiceClass(CognitoAuthenticationFilter.class);
        setServiceConfigClass(CognitoAuthenticationFilterConfig.class);
    }
}
