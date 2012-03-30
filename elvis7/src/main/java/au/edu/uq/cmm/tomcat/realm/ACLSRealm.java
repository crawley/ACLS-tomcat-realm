package au.edu.uq.cmm.tomcat.realm;
import java.security.Principal;
import java.util.Collections;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;

import au.edu.uq.cmm.aclslib.authenticator.Authenticator;
import au.edu.uq.cmm.aclslib.message.AclsException;


public class ACLSRealm extends RealmBase {
    
    private Authenticator authenticator;
    private int serverPort = 1024;
    private String dummyFacility;
    private String serverHost;
    private String localHostId;
    
    @Override
    protected String getName() {
        return "ACLS";
    }

    @Override
    protected String getPassword(String password) {
        throw new UnsupportedOperationException("getPassword");
    }

    @Override
    protected Principal getPrincipal(String userName) {
        return new GenericPrincipal(userName, "",
                Collections.singletonList("ROLE_USER"));
    }

    @Override
    public Principal authenticate(String username, String clientDigest,
            String nonce, String nc, String cnonce,
            String qop, String realm,
            String md5a2) {
        throw new UnsupportedOperationException(
                "ACLS cannot do digest-based authentication");
    }

    @Override
    public Principal authenticate(String userName, String password) {
        Principal res = null;
        try {
            if (userName == null || userName.isEmpty()) {
                containerLog.info("Null or empty j_username");
            } else if (password == null) {
                containerLog.info("Null j_password");
            }
            if (!authenticator.authenticate(userName, password)) {
                if (containerLog.isTraceEnabled()) {
                    containerLog.trace(sm.getString("realmBase.authenticateFailure",
                            userName));
                }
            } else {
                if (containerLog.isTraceEnabled()) {
                    containerLog.trace(sm.getString("realmBase.authenticateSuccess",
                            userName));
                res = getPrincipal(userName);
                }
            }
        } catch (AclsException ex) {
            containerLog.info("ACLS authentication failure", ex);
        }
        return res;
    }

    @Override
    public void startInternal() throws LifecycleException {
        super.startInternal();
        authenticator = new Authenticator(
                serverHost, serverPort, dummyFacility, localHostId);
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public String getDummyFacility() {
        return dummyFacility;
    }

    public void setDummyFacility(String dummyFacility) {
        this.dummyFacility = dummyFacility;
    }

    public String getServerHost() {
        return serverHost;
    }

    public void setServerHost(String serverHost) {
        this.serverHost = serverHost;
    }

    public String getLocalHostId() {
        return localHostId;
    }

    public void setLocalHostId(String localHostId) {
        this.localHostId = localHostId;
    }
}
