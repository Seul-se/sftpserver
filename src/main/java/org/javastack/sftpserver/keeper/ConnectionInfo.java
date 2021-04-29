package org.javastack.sftpserver.keeper;

import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

public class ConnectionInfo {

    private String sourceIp;

    private int sourcePort;

    private String targetIp;

    private int targetPort;

    private String userName;

    private Date createTime;

    private AtomicInteger channelNum = new AtomicInteger();


    private final AtomicInteger bandwidth = new AtomicInteger();

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public String getTargetIp() {
        return targetIp;
    }

    public void setTargetIp(String targetIp) {
        this.targetIp = targetIp;
    }

    public int getTargetPort() {
        return targetPort;
    }

    public void setTargetPort(int targetPort) {
        this.targetPort = targetPort;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public Date getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public int getBandwidth() {
        return bandwidth.get();
    }

    public void addBandwidth(int bandwidth) {
        this.bandwidth.getAndAdd(bandwidth);
    }

    public int getChannelNum(){
        return channelNum.get();
    }
    public void addChannelNum(int num){
        channelNum.getAndAdd(num);
    }

    public boolean equals(Object o){
        if(o instanceof ConnectionInfo){
            if(((ConnectionInfo) o).getSourceIp().equals(sourceIp)&&((ConnectionInfo) o).getSourcePort() == sourcePort){
                return true;
            }
        }
        return false;
    }
}
