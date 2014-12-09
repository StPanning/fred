package freenet.node;

public class JFKMessage3 extends AbstractJFKMessage {
    private byte[] m_nonce;
    private byte[] m_nonceResponder;
    private byte[] m_peerExp;
    private byte[] m_authenticator;

    public JFKMessage3(byte[] nonce, byte[] nonceResponder,
                       byte[] hisExp, byte[] authenticator){
        m_nonce = nonce;
        m_nonceResponder = nonceResponder;
        m_peerExp = hisExp;
        m_authenticator = authenticator;
    }

    public final byte[]
    getNI(){
        return m_nonce;
    }

    public final byte[]
    getNonceResponder(){
        return m_nonceResponder;
    }

    public final byte[]
    getPeerExponent(){
        return m_peerExp;
    }

    public final byte[]
    getAuthenticator(){
        return m_authenticator;
    }

    public void
    send(JFKHandshakeInterface ji){
        ji.send(this);
    }
}
