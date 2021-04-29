//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apache.sshd.server.session;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexFactoryManager;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.kex.extension.KexExtensionHandler;
import org.apache.sshd.common.kex.extension.KexExtensionHandler.AvailabilityPhase;
import org.apache.sshd.common.kex.extension.KexExtensionHandler.KexPhase;
import org.apache.sshd.common.keyprovider.HostKeyCertificateProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.session.SessionDisconnectHandler;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.ServerAuthenticationManager;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.auth.UserAuthFactory;
import org.apache.sshd.server.auth.WelcomeBannerPhase;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.auth.hostbased.HostBasedAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;

public abstract class AbstractServerSession extends AbstractSession implements ServerSession {
    private ServerProxyAcceptor proxyAcceptor;
    private SocketAddress clientAddress;
    private PasswordAuthenticator passwordAuthenticator;
    private PublickeyAuthenticator publickeyAuthenticator;
    private KeyboardInteractiveAuthenticator interactiveAuthenticator;
    private GSSAuthenticator gssAuthenticator;
    private HostBasedAuthenticator hostBasedAuthenticator;
    private List<UserAuthFactory> userAuthFactories;
    private KeyPairProvider keyPairProvider;
    private HostKeyCertificateProvider hostKeyCertificateProvider;

    protected AbstractServerSession(ServerFactoryManager factoryManager, IoSession ioSession) {
        super(true, factoryManager, ioSession);
    }

    public ServerFactoryManager getFactoryManager() {
        return (ServerFactoryManager)super.getFactoryManager();
    }

    public ServerProxyAcceptor getServerProxyAcceptor() {
        return (ServerProxyAcceptor)this.resolveEffectiveProvider(ServerProxyAcceptor.class, this.proxyAcceptor, this.getFactoryManager().getServerProxyAcceptor());
    }

    public void setServerProxyAcceptor(ServerProxyAcceptor proxyAcceptor) {
        this.proxyAcceptor = proxyAcceptor;
    }

    public SocketAddress getClientAddress() {
        return this.resolvePeerAddress(this.clientAddress);
    }

    public void setClientAddress(SocketAddress clientAddress) {
        this.clientAddress = clientAddress;
    }

    public PasswordAuthenticator getPasswordAuthenticator() {
        ServerFactoryManager manager = this.getFactoryManager();
        return (PasswordAuthenticator)this.resolveEffectiveProvider(PasswordAuthenticator.class, this.passwordAuthenticator, manager.getPasswordAuthenticator());
    }

    public void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator) {
        this.passwordAuthenticator = passwordAuthenticator;
    }

    public PublickeyAuthenticator getPublickeyAuthenticator() {
        ServerFactoryManager manager = this.getFactoryManager();
        return (PublickeyAuthenticator)this.resolveEffectiveProvider(PublickeyAuthenticator.class, this.publickeyAuthenticator, manager.getPublickeyAuthenticator());
    }

    public void setPublickeyAuthenticator(PublickeyAuthenticator publickeyAuthenticator) {
        this.publickeyAuthenticator = publickeyAuthenticator;
    }

    public KeyboardInteractiveAuthenticator getKeyboardInteractiveAuthenticator() {
        ServerFactoryManager manager = this.getFactoryManager();
        return (KeyboardInteractiveAuthenticator)this.resolveEffectiveProvider(KeyboardInteractiveAuthenticator.class, this.interactiveAuthenticator, manager.getKeyboardInteractiveAuthenticator());
    }

    public void setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator interactiveAuthenticator) {
        this.interactiveAuthenticator = interactiveAuthenticator;
    }

    public GSSAuthenticator getGSSAuthenticator() {
        ServerFactoryManager manager = this.getFactoryManager();
        return (GSSAuthenticator)this.resolveEffectiveProvider(GSSAuthenticator.class, this.gssAuthenticator, manager.getGSSAuthenticator());
    }

    public void setGSSAuthenticator(GSSAuthenticator gssAuthenticator) {
        this.gssAuthenticator = gssAuthenticator;
    }

    public HostBasedAuthenticator getHostBasedAuthenticator() {
        ServerFactoryManager manager = this.getFactoryManager();
        return (HostBasedAuthenticator)this.resolveEffectiveProvider(HostBasedAuthenticator.class, this.hostBasedAuthenticator, manager.getHostBasedAuthenticator());
    }

    public void setHostBasedAuthenticator(HostBasedAuthenticator hostBasedAuthenticator) {
        this.hostBasedAuthenticator = hostBasedAuthenticator;
    }

    public List<UserAuthFactory> getUserAuthFactories() {
        ServerFactoryManager manager = this.getFactoryManager();
        return (List)this.resolveEffectiveFactories(this.userAuthFactories, manager.getUserAuthFactories());
    }

    public void setUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
        this.userAuthFactories = userAuthFactories;
    }

    public KeyPairProvider getKeyPairProvider() {
        KexFactoryManager parent = this.getDelegate();
        return (KeyPairProvider)this.resolveEffectiveProvider(KeyPairProvider.class, this.keyPairProvider, parent == null ? null : ((ServerAuthenticationManager)parent).getKeyPairProvider());
    }

    public HostKeyCertificateProvider getHostKeyCertificateProvider() {
        ServerFactoryManager manager = this.getFactoryManager();
        return (HostKeyCertificateProvider)this.resolveEffectiveProvider(HostKeyCertificateProvider.class, this.hostKeyCertificateProvider, manager.getHostKeyCertificateProvider());
    }

    public void setHostKeyCertificateProvider(HostKeyCertificateProvider hostKeyCertificateProvider) {
        this.hostKeyCertificateProvider = hostKeyCertificateProvider;
    }

    public void setKeyPairProvider(KeyPairProvider keyPairProvider) {
        this.keyPairProvider = keyPairProvider;
    }

    protected IoWriteFuture sendServerIdentification(String... headerLines) throws IOException {
        this.serverVersion = this.resolveIdentificationString("server-identification");
        String ident = this.serverVersion;
        if (GenericUtils.length(headerLines) > 0) {
            ident = GenericUtils.join(headerLines, "\r\n") + "\r\n" + this.serverVersion;
        }

        return this.sendIdentification(ident);
    }

    protected void checkKeys() {
    }

    protected boolean handleServiceRequest(String serviceName, Buffer buffer) throws Exception {
        boolean started = super.handleServiceRequest(serviceName, buffer);
        if (!started) {
            return false;
        } else {
            if ("ssh-userauth".equals(serviceName) && this.currentService instanceof ServerUserAuthService) {
                ServerUserAuthService authService = (ServerUserAuthService)this.currentService;
                if (WelcomeBannerPhase.IMMEDIATE.equals(authService.getWelcomePhase())) {
                    authService.sendWelcomeBanner(this);
                }
            }

            return true;
        }
    }

    public void startService(String name, Buffer buffer) throws Exception {
        FactoryManager factoryManager = this.getFactoryManager();
        this.currentService = ServiceFactory.create(factoryManager.getServiceFactories(), ValidateUtils.checkNotNullAndNotEmpty(name, "No service name specified"), this);
        if (this.currentService == null) {
            try {
                SessionDisconnectHandler handler = this.getSessionDisconnectHandler();
                if (handler != null && handler.handleUnsupportedServiceDisconnectReason(this, 5, name, buffer)) {
                    if (this.log.isDebugEnabled()) {
                        this.log.debug("startService({}) ignore unknown service={} by handler", this, name);
                    }

                    return;
                }
            } catch (RuntimeException | IOException var5) {
                this.log.warn("startService({})[{}] failed ({}) to invoke disconnect handler: {}", new Object[]{this, name, var5.getClass().getSimpleName(), var5.getMessage()});
                if (this.log.isDebugEnabled()) {
                    this.log.warn("startService(" + this + ")[" + name + "] disconnect handler invocation exception details", var5);
                }
            }

            throw new SshException(7, "Unknown service: " + name);
        }
    }

    public IoWriteFuture signalAuthenticationSuccess(String username, String authService, Buffer buffer) throws Exception {
        KexState curState = (KexState)this.kexState.get();
        if (!KexState.DONE.equals(curState)) {
            throw new SshException(2, "Authentication success signalled though KEX state=" + curState);
        } else {
            KexExtensionHandler extHandler = this.getKexExtensionHandler();
            if (extHandler != null && extHandler.isKexExtensionsAvailable(this, AvailabilityPhase.AUTHOK)) {
                extHandler.sendKexExtensions(this, KexPhase.AUTHOK);
            }

            Buffer response = this.createBuffer((byte)52, 8);
            IoSession networkSession = this.getIoSession();
            IoWriteFuture future;
            synchronized(this.encodeLock) {
                Buffer packet = this.resolveOutputPacket(response);
                this.setUsername(username);
                this.setAuthenticated();
                this.startService(authService, buffer);
                future = networkSession.writePacket(packet);
            }

            this.resetIdleTimeout();
            this.log.info("Session {}@{} authenticated", username, networkSession.getRemoteAddress());
            return future;
        }
    }

    protected void handleServiceAccept(String serviceName, Buffer buffer) throws Exception {
        super.handleServiceAccept(serviceName, buffer);

        try {
            SessionDisconnectHandler handler = this.getSessionDisconnectHandler();
            if (handler != null && handler.handleUnsupportedServiceDisconnectReason(this, 6, serviceName, buffer)) {
                if (this.log.isDebugEnabled()) {
                    this.log.debug("handleServiceAccept({}) ignore unknown service={} by handler", this, serviceName);
                }

                return;
            }
        } catch (RuntimeException | IOException var4) {
            this.log.warn("handleServiceAccept({}) failed ({}) to invoke disconnect handler of unknown service={}: {}", new Object[]{this, var4.getClass().getSimpleName(), serviceName, var4.getMessage()});
            if (this.log.isDebugEnabled()) {
                this.log.warn("handleServiceAccept(" + this + ")[" + serviceName + "] handler invocation exception details", var4);
            }
        }

        this.disconnect(2, "Unsupported packet: SSH_MSG_SERVICE_ACCEPT for " + serviceName);
    }

    protected byte[] sendKexInit(Map<KexProposalOption, String> proposal) throws IOException {
        this.mergeProposals(this.serverProposal, proposal);
        return super.sendKexInit(proposal);
    }

    protected void setKexSeed(byte... seed) {
        this.setServerKexData(seed);
    }

    protected String resolveAvailableSignaturesProposal(FactoryManager proposedManager) throws IOException, GeneralSecurityException {
        ValidateUtils.checkTrue(proposedManager == this.getFactoryManager(), "Mismatched signatures proposed factory manager");
        KeyPairProvider kpp = this.getKeyPairProvider();
        boolean debugEnabled = this.log.isDebugEnabled();
        Collection provided = null;

        try {
            if (kpp != null) {
                provided = (Collection)GenericUtils.stream(kpp.getKeyTypes(this)).collect(Collectors.toSet());
                HostKeyCertificateProvider hostKeyCertificateProvider = this.getHostKeyCertificateProvider();
                if (hostKeyCertificateProvider != null) {
                    Iterable<OpenSshCertificate> certificates = hostKeyCertificateProvider.loadCertificates(this);
                    Iterator var7 = certificates.iterator();

                    while(var7.hasNext()) {
                        OpenSshCertificate certificate = (OpenSshCertificate)var7.next();
                        String rawKeyType = certificate.getRawKeyType();
                        if (provided.contains(rawKeyType)) {
                            provided.add(certificate.getKeyType());
                        } else {
                            this.log.info("resolveAvailableSignaturesProposal({}) No private key of type={} available in provided certificate", this, rawKeyType);
                        }
                    }
                }
            }
        } catch (Error var10) {
            this.log.warn("resolveAvailableSignaturesProposal({}) failed ({}) to get key types: {}", new Object[]{this, var10.getClass().getSimpleName(), var10.getMessage()});
            if (debugEnabled) {
                this.log.warn("resolveAvailableSignaturesProposal(" + this + ") fetch key types failure details", var10);
            }

            throw new RuntimeSshException(var10);
        }

        Collection<String> available = NamedResource.getNameList(this.getSignatureFactories());
        if (provided != null && !GenericUtils.isEmpty(available)) {
            Collection<String> supported = SignatureFactory.resolveSignatureFactoryNamesProposal(provided, available);
            return GenericUtils.isEmpty(supported) ? this.resolveEmptySignaturesProposal(available, provided) : GenericUtils.join(supported, ',');
        } else {
            return this.resolveEmptySignaturesProposal(available, provided);
        }
    }

    protected String resolveEmptySignaturesProposal(Iterable<String> supported, Iterable<String> provided) {
        if (this.log.isDebugEnabled()) {
            this.log.debug("resolveEmptySignaturesProposal({})[{}] none of the keys appears in supported list: {}", new Object[]{this, provided, supported});
        }

        return null;
    }

    protected boolean readIdentification(Buffer buffer) throws Exception {
        ServerProxyAcceptor acceptor = this.getServerProxyAcceptor();
        int rpos = buffer.rpos();
        boolean debugEnabled = this.log.isDebugEnabled();
        if (acceptor != null) {
            try {
                boolean completed = acceptor.acceptServerProxyMetadata(this, buffer);
                if (!completed) {
                    buffer.rpos(rpos);
                    return false;
                }
            } catch (Throwable var9) {
                this.log.warn("readIdentification({}) failed ({}) to accept proxy metadata: {}", new Object[]{this, var9.getClass().getSimpleName(), var9.getMessage()});
                if (debugEnabled) {
                    this.log.warn("readIdentification(" + this + ") proxy metadata acceptance failure details", var9);
                }

                if (var9 instanceof IOException) {
                    throw (IOException)var9;
                }

                throw new SshException(var9);
            }
        }
        List<String> ident;
        List<String> ipStr = this.doReadIdentification(buffer, true);
        if(ipStr.size()>0&&ipStr.get(0).startsWith("PROXY")) {
            String line = ipStr.get(0);
            this.log.info(line + " connected");
            String[] tmp = line.split(" ");
            if(tmp.length>=6) {
                String sourceIP = tmp[2];
                String sourcePort = tmp[4];
                try {
                    this.setClientAddress(new InetSocketAddress(sourceIP, Integer.parseInt(sourcePort)));
                }catch (Exception e){
                    this.log.error("Proxy parse failed!!",e);
                }
            }
            ident = this.doReadIdentification(buffer, true);
        }else{
            ident = ipStr;
        }
        int numLines = GenericUtils.size(ident);
        this.clientVersion = numLines <= 0 ? null : (String)ident.remove(numLines - 1);
        if (GenericUtils.isEmpty(this.clientVersion)) {
            buffer.rpos(rpos);
            return false;
        } else {
            if (debugEnabled) {
                this.log.debug("readIdentification({}) client version string: {}", this, this.clientVersion);
            }

            SshException err;
            if (SessionContext.isValidVersionPrefix(this.clientVersion)) {
                err = numLines > 1 ? new SshException(2, "Unexpected extra " + (numLines - 1) + " lines from client=" + this.clientVersion) : null;
            } else {
                err = new SshException(8, "Unsupported protocol version: " + this.clientVersion);
            }

            if (err != null) {
                IoSession networkSession = this.getIoSession();
                networkSession.writePacket(new ByteArrayBuffer((err.getMessage() + "\n").getBytes(StandardCharsets.UTF_8))).addListener((future) -> {
                    this.close(true);
                });
                throw err;
            } else {
                this.signalPeerIdentificationReceived(this.clientVersion, ident);
                this.kexState.set(KexState.INIT);
                this.sendKexInit();
                return true;
            }
        }
    }

    protected void receiveKexInit(Map<KexProposalOption, String> proposal, byte[] seed) throws IOException {
        this.mergeProposals(this.clientProposal, proposal);
        this.setClientKexData(seed);
    }

    public KeyPair getHostKey() {
        String proposedKey = this.getNegotiatedKexParameter(KexProposalOption.SERVERKEYS);
        String keyType = KeyUtils.getCanonicalKeyType(proposedKey);
        KeyPairProvider provider = (KeyPairProvider)Objects.requireNonNull(this.getKeyPairProvider(), "No host keys provider");

        try {
            HostKeyCertificateProvider hostKeyCertificateProvider = this.getHostKeyCertificateProvider();
            if (hostKeyCertificateProvider != null) {
                OpenSshCertificate publicKey = hostKeyCertificateProvider.loadCertificate(this, keyType);
                if (publicKey != null) {
                    String rawKeyType = publicKey.getRawKeyType();
                    if (this.log.isDebugEnabled()) {
                        this.log.debug("getHostKey({}) using certified key {}/{} with ID={}", new Object[]{this, keyType, rawKeyType, publicKey.getId()});
                    }

                    KeyPair keyPair = provider.loadKey(this, rawKeyType);
                    ValidateUtils.checkNotNull(keyPair, "No certified private key of type=%s available", rawKeyType);
                    return new KeyPair(publicKey, keyPair.getPrivate());
                }
            }

            return provider.loadKey(this, keyType);
        } catch (GeneralSecurityException | Error | IOException var8) {
            this.log.warn("getHostKey({}) failed ({}) to load key of type={}[{}]: {}", new Object[]{this, var8.getClass().getSimpleName(), proposedKey, keyType, var8.getMessage()});
            if (this.log.isDebugEnabled()) {
                this.log.warn("getHostKey(" + this + ") " + proposedKey + "[" + keyType + "] key load failure details", var8);
            }

            throw new RuntimeSshException(var8);
        }
    }

    public int getActiveSessionCountForUser(String userName) {
        if (GenericUtils.isEmpty(userName)) {
            return 0;
        } else {
            IoSession networkSession = this.getIoSession();
            IoService service = networkSession.getService();
            Map<?, IoSession> sessionsMap = service.getManagedSessions();
            if (GenericUtils.isEmpty(sessionsMap)) {
                return 0;
            } else {
                int totalCount = 0;
                Iterator var6 = sessionsMap.values().iterator();

                while(var6.hasNext()) {
                    IoSession is = (IoSession)var6.next();
                    ServerSession session = (ServerSession)getSession(is, true);
                    if (session != null) {
                        String sessionUser = session.getUsername();
                        if (!GenericUtils.isEmpty(sessionUser) && Objects.equals(sessionUser, userName)) {
                            ++totalCount;
                        }
                    }
                }

                return totalCount;
            }
        }
    }

    public long getId() {
        IoSession networkSession = this.getIoSession();
        return networkSession.getId();
    }

    protected ConnectionService getConnectionService() {
        return this.currentService instanceof ConnectionService ? (ConnectionService)this.currentService : null;
    }
}
