package freenet.node;

public class JFKMessage1 extends AbstractJFKMessage {
    private byte [] m_peerExponent;
    private boolean m_unknownInitiator;
    private int    m_setupType;
    public JFKMessage1(byte[] peerExponent, boolean unknownInitiator,
                       int setupType) {
        m_peerExponent     = peerExponent;
        m_unknownInitiator = unknownInitiator;
        m_setupType        = setupType;
    }
    public byte[]
    getPeerExponent(){
        return m_peerExponent;
    }

    public void send(JFKHandshakeInterface ji){
        ji.send(this);
    }

    public boolean istUnknownInitiator(){
        return m_unknownInitiator;
    }

    public int getSetupType(){
        return m_setupType;
    }

}
