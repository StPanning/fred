package freenet.node;

public class JFKMessage1 extends AbstractJFKMessage {
    private byte [] m_peerExponent;
    public JFKMessage1(byte[] peerExponent) {
        super(negType, pn, replyPeer);
        m_peerExponent = peerExponent;
    }
    public byte[]
    getPeerExponent(){
        return m_peerExponent;
    }
    public void send(FNPPacketMangler pm){
        pm.send(this);
    }
}
