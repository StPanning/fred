package freenet.node;

import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import freenet.support.ByteArrayWrapper;

public abstract class AbstractFNPPacketParser implements CipherSpecs {

    public static AbstractFNPPacketParser
        createInstance(NodeCrypto nc,int negType)
        throws FNPPacketException{
        switch(negType){
        case  9:
        case 10:
            return new FNPPacketParser10(nc,
                                         new CipherSpecsV10Adapter());
        default:
            throw new FNPPacketException("unsupported negType");
        }
    }

    private CipherSpecs m_cs;

    protected AbstractFNPPacketParser(CipherSpecs cs){
        m_cs         = cs;
    }

    public abstract AbstractJFKMessage
    readMessage1(byte payload[], int offset,
                     boolean unknownInitiator)
        throws FNPPacketException;
    public abstract AbstractJFKMessage
    readMessage2(byte payload[], int offset,
                 ECPublicKey peerPubkey,
                 byte[] peerKeyHash,
                 LinkedList<byte[]> noncesSent,
                 HashMap<ByteArrayWrapper, byte[]> authenticatorCache)
        throws FNPPacketException;
//    public abstract AbstractJFKMessage
//    readMessage3(byte payload[], boolean unknownInitiator);
//    public abstract AbstractJFKMessage
//    readMessage4(byte payload[], boolean unknownInitiator);
//
    public final int
    getNonceSize(){
        return m_cs.getNonceSize();
    }
    public final int
    getSignatureLength() {
        return m_cs.getSignatureLength();
    }
    public final int
    getModulusLength(){
        return m_cs.getModulusLength();
    }
}
