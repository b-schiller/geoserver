package org.geoserver.web.security.cognito;

import java.util.logging.Logger;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.model.IModel;
import org.geoserver.security.cognito.CognitoAuthenticationFilterConfig;
import org.geoserver.security.web.auth.AuthenticationFilterPanel;
import org.geoserver.web.wicket.HelpLink;
import org.geotools.util.logging.Logging;

public class CognitoAuthFilterPanel
        extends AuthenticationFilterPanel<CognitoAuthenticationFilterConfig> {

    private static final Logger LOG = Logging.getLogger(CognitoAuthFilterPanel.class);

    private static final long serialVersionUID = 1L;

    public CognitoAuthFilterPanel(String id, IModel<CognitoAuthenticationFilterConfig> model) {
        super(id, model);
        add(new HelpLink("userPoolHelp", this).setDialog(this.dialog));
        add(new TextField<String>("awsRegion"));
        add(new TextField<String>("userPoolID"));
        add(new TextField<String>("clientID"));
        add(new TextField<String>("jwksFilePath"));
    }

    @Override
    public void doLoad(CognitoAuthenticationFilterConfig config) throws Exception {
        getSecurityManager().loadFilter(config.getName());
    }

    @Override
    public void doSave(CognitoAuthenticationFilterConfig config) throws Exception {
        getSecurityManager().saveFilter(config);
    }
}
