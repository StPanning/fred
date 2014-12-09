package freenet.node;

public class JFKMessage3Cached extends AbstractJFKMessage {
    private byte[] m_cachedMsg;
    public JFKMessage3Cached(byte[] cachedMsg){
        m_cachedMsg = cachedMsg;
    }
    public final byte[]
    cachedMessage(){
        return m_cachedMsg;
    }

    public void
    send(FNPPacketMangler pm){
        pm.send(this);
    }
}
