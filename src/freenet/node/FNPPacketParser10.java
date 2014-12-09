package freenet.node;

import freenet.io.comm.Peer;
import freenet.crypt.ECDH;
import freenet.crypt.ECDSA.Curves;
import freenet.crypt.ECDSA.Curves;
import freenet.crypt.ECDSA;
import freenet.crypt.SHA256;
import freenet.support.ByteArrayWrapper;
import freenet.support.HexUtil;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

public class FNPPacketParser10 extends AbstractFNPPacketParser {
    private NodeCrypto m_nodeCrypto;

    protected FNPPacketParser10(NodeCrypto nc, CipherSpecs cs){
        super(cs);
        m_nodeCrypto = nc;
    }

    public AbstractJFKMessage
        readMessage1(byte payload[], int offset,
                     boolean unknownInitiator)
        throws FNPPacketException{
        //why '+ 3'?
        int expected_len = getNonceSize() + getModulusLength() + 3;
        if(true == unknownInitiator){
            expected_len += NodeCrypto.IDENTITY_LENGTH;
        }
        if(payload.length < expected_len){
            StringBuffer err_msg = new StringBuffer();
            err_msg.append("packet to short. Is: " );
            err_msg.append(payload.length);
            err_msg.append("should be: ");
            err_msg.append(expected_len);

            throw new FNPPacketException(err_msg.toString());
        }
        byte[] nonceInitiator = new byte[getNonceSize()];
        System.arraycopy(payload, offset, nonceInitiator,
                         0, getNonceSize());
        offset += getNonceSize();
        byte[] hisExp = Arrays.copyOfRange(payload,
                                           offset,
                                           offset + getModulusLength());
        if(true == unknownInitiator){
            offset += getModulusLength();
            byte[] expIdentHash = Arrays.copyOfRange(
                payload, offset,
                offset + NodeCrypto.IDENTITY_LENGTH);

            if(!MessageDigest.isEqual(expIdentHash, m_nodeCrypto.identityHash)) {
                StringBuffer err_msg = new StringBuffer();
                err_msg.append("Invalid unknown-initiator JFK(1), IDr' is ");
                err_msg.append(HexUtil.bytesToHex(expIdentHash));
                err_msg.append(" should be ");
                err_msg.append(HexUtil.bytesToHex(m_nodeCrypto.identityHash));
                throw new FNPPacketException(err_msg.toString());
            }
        }
        return new JFKMessage1(hisExp);
    }

    public AbstractJFKMessage
    readMessage2(byte payload[], int offset,
                 java.security.interfaces.ECPublicKey peerPubkey,
                 byte[] peerKeyHash,
                 LinkedList<byte[]> noncesSent,
                 HashMap<ByteArrayWrapper, byte[]> authenticatorCache)
        throws FNPPacketException {
	int expected_len = getNonceSize()
                          + getModulusLength()
                          + SHA256.getDigestLength() * 3;
        //why + 3
        if(payload.length < expected_len + 3) {
            StringBuffer err_msg = new StringBuffer();
            err_msg.append("Packet too short: ");
            err_msg.append(payload.length);
            err_msg.append(" after decryption in JFK(2), should be ");
            err_msg.append(expected_len + 3);
            throw new FNPPacketException(err_msg.toString());
        }
        byte[] nonceInitiator = new byte[SHA256.getDigestLength()];
        System.arraycopy(payload, offset, nonceInitiator,
                         0, SHA256.getDigestLength());
        offset += SHA256.getDigestLength();
        byte[] nonceResponder = new byte[getNonceSize()];
        System.arraycopy(payload, offset,
                         nonceResponder, 0, getNonceSize());
        offset += getNonceSize();
        byte[] hisExp = Arrays.copyOfRange(payload, offset,
                                           offset+getModulusLength());
        offset += getModulusLength();
        byte[] sig = new byte[getSignatureLength()];
        System.arraycopy(payload, offset,
                         sig, 0, getSignatureLength());
        offset += getSignatureLength();
        byte[] authenticator = Arrays.copyOfRange(payload, offset,
                                                  offset + SHA256.getDigestLength());
        Object message3 = null;
        synchronized (authenticatorCache) {
            message3 = authenticatorCache.get(new ByteArrayWrapper(authenticator));
        }

	if(message3 != null) {
            return new JFKMessage3Cached((byte[]) message3);
        }

        byte[] myNi = null;
        for(byte[] buf : noncesSent) {
            if(MessageDigest.isEqual(nonceInitiator,
                                     SHA256.digest(buf))){
                myNi = buf;
            }
        }

        if(myNi == null){
            throw new FNPPacketException("unexpected jfk(2) message");
        }

        if(!ECDSA.verify(Curves.P256, peerPubkey, sig, hisExp)) {
            String e = "ECDSA signature verification has failed";
            throw new FNPPacketException(e);
        }
        return new JFKMessage3( myNi, nonceResponder,
                               hisExp, authenticator);
    }
}
