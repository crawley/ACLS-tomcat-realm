package au.edu.uq.cmm.tomcat.realm;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;

import au.edu.uq.cmm.aclslib.authenticator.AclsAuthenticator;
import au.edu.uq.cmm.aclslib.message.AclsClient;
import au.edu.uq.cmm.aclslib.message.AclsException;


public class ACLSRealm extends RealmBase {
    private AclsAuthenticator authenticator;
    private int serverPort = 1024;
    private String dummyFacility;
    private String serverHost;
    private int timeout = AclsClient.ACLS_REQUEST_TIMEOUT * 2;
    private String localHostId;
    private List roles = Arrays.asList(
            new String[]{"ROLE_USER", "ROLE_ACLS_USER"});
    
    protected String getName() {
        return "ACLS";
    }

    protected String getPassword(String password) {
        throw new UnsupportedOperationException("getPassword");
    }

    protected Principal getPrincipal(String userName) {
        return getPrincipal(userName, "");
    }

    protected Principal getPrincipal(String userName, String password) {
        return new GenericPrincipal(this, userName, password, roles);
    }
    
    public Principal authenticate(String username, String clientDigest,
            String nonce, String nc, String cnonce,
            String qop, String realm,
            String md5a2) {
        throw new UnsupportedOperationException(
                "ACLS cannot do digest-based authentication");
    }

    public Principal authenticate(String userName, String password) {
        Principal res = null;
        try {
            if (userName == null || userName.isEmpty()) {
                containerLog.info("Null or empty j_username");
            } else if (password == null) {
                containerLog.info("Null j_password");
            } else if (authenticator.authenticate(userName, password, null) == null) {
                if (containerLog.isTraceEnabled()) {
                    containerLog.trace(sm.getString("realmBase.authenticateFailure",
                            userName));
                }
            } else {
                if (containerLog.isTraceEnabled()) {
                    containerLog.trace(sm.getString("realmBase.authenticateSuccess",
                            userName));
                }
                res = getPrincipal(userName, password);
            }
        } catch (AclsException ex) {
            containerLog.info("ACLS authentication failure", ex);
        }
        return res;
    }

    public void init() {
        super.init();
        authenticator = new AclsAuthenticator(
                serverHost, serverPort, timeout, dummyFacility, localHostId);
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

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }
}
