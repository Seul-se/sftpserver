package org.javastack.sftpserver.keeper;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ServerStatus {

    public Map<String, List<ConnectionInfo>> getAllConnection() {
        return allConnection;
    }

    private final Map<String,List<ConnectionInfo>> allConnection = new ConcurrentHashMap<>();


}
