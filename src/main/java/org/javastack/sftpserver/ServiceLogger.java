package org.javastack.sftpserver;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PublicKey;
import java.util.*;

import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.subsystem.sftp.FileHandle;
import org.apache.sshd.server.subsystem.sftp.Handle;
import org.apache.sshd.server.subsystem.sftp.SftpEventListener;
import org.javastack.sftpserver.keeper.ConnectionInfo;
import org.slf4j.event.Level;

public class ServiceLogger extends AbstractLoggingBean implements SftpEventListener, SessionListener {
	private boolean logRequest = false;

	private Server server;

	ServiceLogger(Server server) {
		super();
		this.server = server;
	}

	public void setLogRequest(final boolean logRequest) {
		this.logRequest = logRequest;
	}

	private static final String toHuman(final Session session, final String username) {
		final IoSession networkSession = session.getIoSession();
		final SocketAddress peerAddress = (networkSession == null) ? null : networkSession.getRemoteAddress();
		return (username == null ? "<unknown>" : username) + "@" + addrToHuman(peerAddress);
	}

	private static final String toHuman(final Session session) {
		return toHuman(session, session.getUsername());
	}

	private static final String addrToHuman(final SocketAddress addr) {
		if (addr instanceof InetSocketAddress) {
			final InetSocketAddress a = (InetSocketAddress) addr;
			return (a.getHostString() + ":" + a.getPort());
		}
		return String.valueOf(addr);
	}

	private final void logLevel(final String msg, final Level level) {
		switch (level) {
		case INFO:
			log.info(msg);
			break;
		case ERROR:
			log.error(msg);
			break;
		case WARN:
			log.warn(msg);
			break;
		case DEBUG:
			log.debug(msg);
			break;
		case TRACE:
			log.trace(msg);
			break;
		}
	}

	// Auth Logger

	public void authPasswordPreLogin(final ServerSession session, final String username) {
		log.info("auth password(" + toHuman(session, username) + ")");
	}

	public void authPublicKeyPreLogin(final ServerSession session, final String username, final PublicKey key) {
		final String keyType = (key == null ? "<unknown>" : key.getAlgorithm());
		log.info("auth publickey(" + toHuman(session, username) + ") type: " + keyType);
	}

	public void authPasswordPostLogin(final ServerSession session, final String username, final Level level,
			final String info) {
		Connected(session,username);
		logLevel("auth password(" + toHuman(session, username) + ") info: " + info, level);
	}

	public void authPublicKeyPostLogin(final ServerSession session, final String username, final PublicKey key,
			final Level level, final String info) {
		Connected(session,username);
		final String keyType = (key == null ? "<unknown>" : key.getAlgorithm());
		logLevel("auth publickey(" + toHuman(session, username) + ") type: " + keyType //
				+ " info: " + info, level);
	}

	private void Connected(final ServerSession session,String username){
		String sourceIP = ((InetSocketAddress)session.getClientAddress()).getHostString();
		int sourcePort = ((InetSocketAddress)session.getClientAddress()).getPort();
		Map<String, List<ConnectionInfo>> allConnection = server.getServerStatus().getAllConnection();
		List<ConnectionInfo> connectionInfos = allConnection.get(username);
		if(connectionInfos == null){
			synchronized (allConnection){
				connectionInfos = allConnection.get(username);
				if(connectionInfos == null){
					connectionInfos = new Vector<>();
					allConnection.put(username,connectionInfos);
				}
			}
		}
		ConnectionInfo connectionInfo = new ConnectionInfo();
		connectionInfo.setCreateTime(new Date());
		connectionInfo.setSourceIp(sourceIP);
		connectionInfo.setSourcePort(sourcePort);
		connectionInfo.setUserName(username);
		connectionInfos.add(connectionInfo);
	}
	// Session Logger

	@Override
	public void sessionCreated(final Session session) {
		if (log.isInfoEnabled()) {
			log.info("session created(" + toHuman(session) + ")");
		}
	}

	@Override
	public void sessionDisconnect(final Session session, final int reason, final String msg, final String language,
			final boolean initiator) {
		if (log.isInfoEnabled()) {
			log.info("session disconnect(" + toHuman(session) + ") reason: " + reason + " msg: " + msg);
		}
	}

	@Override
	public void sessionClosed(final Session session) {
		if (log.isInfoEnabled()) {
			log.info("session closed(" + toHuman(session) + ")");
		}
	}

	// Request Logger

	//建立channel
	@Override
	public void initialized(final ServerSession session, final int version) {
		if (log.isInfoEnabled()) {
			log.info("request initialized(" + toHuman(session) + ") version: " + version);
		}
	}

	//断开channel
	@Override
	public void destroying(final ServerSession session) {
		if (log.isInfoEnabled()) {
			log.info("request destroying(" + toHuman(session) + ")");
		}
	}

	//上传文件
	@Override
	public void opening(final ServerSession session, final String remoteHandle, final Handle localHandle)
			throws IOException {
		if(localHandle instanceof FileHandle) {
			FileHandle fh = (FileHandle) localHandle;
			if (fh.getOpenOptions().contains(StandardOpenOption.READ)) {
				//TODO 下载文件
			}
			if (fh.getOpenOptions().contains(StandardOpenOption.WRITE)) {
				//TODO 上传/修改 文件
			}
		}
		if (!logRequest)
			return;
		if (log.isInfoEnabled()) {
			final Path path = localHandle.getFile();
			log.info("request opening(" + toHuman(session) + ")[" + remoteHandle + "][" //
					+ (Files.isDirectory(path) ? "directory" : "file") + "] " + path);
		}
	}

	@Override
	public void closing(final ServerSession session, final String remoteHandle, final Handle localHandle) {
		if(localHandle instanceof FileHandle) {
			FileHandle fh = (FileHandle) localHandle;
			if (fh.getOpenOptions().contains(StandardOpenOption.READ)) {
				//TODO 下载完成
			}
			if (fh.getOpenOptions().contains(StandardOpenOption.WRITE)) {
				//TODO 上传/修改 完成
			}
		}
		if (!logRequest)
			return;
		if (log.isInfoEnabled()) {
			final Path path = localHandle.getFile();
			log.info("request close(" + toHuman(session) + ")[" + remoteHandle + "][" //
					+ (Files.isDirectory(path) ? "dir" : "file") + "] " + path);
		}
	}

	@Override
	public void creating(final ServerSession session, final Path path, final Map<String, ?> attrs) throws IOException {
		if (!logRequest)
			return;
		if (log.isInfoEnabled()) {
			log.info("request creating(" + toHuman(session) + ") " + path);
		}
	}

	@Override
	public void moving(final ServerSession session, final Path srcPath, final Path dstPath,
			final Collection<CopyOption> opts) throws IOException {
		if (!logRequest)
			return;
		if (log.isInfoEnabled()) {
			log.info("request moving(" + toHuman(session) + ")[" //
					+ (Files.isDirectory(srcPath) ? "dir" : "file") + "]" //
					+ opts + " " + srcPath + " => " + dstPath);
		}
	}

	@Override
	public void removing(final ServerSession session, final Path path, final boolean isDirectory) throws IOException {
		if (!logRequest)
			return;
		if (log.isInfoEnabled()) {
			log.info("request removing(" + toHuman(session) + ")[" + (isDirectory ? "dir" : "file") + "] " + path);
		}
	}

	@Override
	public void linking(final ServerSession session, final Path source, final Path target, final boolean symLink)
			throws IOException {
		if (!logRequest)
			return;
		// Must be fail
		if (log.isInfoEnabled()) {
			log.info("request linking(" + toHuman(session) + ")[" + (symLink ? "sym" : "hard") + "] " //
					+ source + " => " + target);
		}
	}

	@Override
	public void modifyingAttributes(final ServerSession session, final Path path, final Map<String, ?> attrs)
			throws IOException {
		if (!logRequest)
			return;
		// Must be fail
		if (log.isInfoEnabled()) {
			log.info("request modifyingAttributes(" + toHuman(session) + ") " + path + ": " + attrs);
		}
	}
}
