package freenet.node;
import freenet.crypt.ECDH;
import freenet.crypt.ECDSA;


public class CipherSpecsV10Adapter
        implements CipherSpecs {

        public int
        getNonceSize(){
            return 16;
        }

        public int
        getSignatureLength(){
            return ECDSA.Curves.P256.maxSigSize;
        }

        public int
        getModulusLength(){
            return ECDH.Curves.P256.modulusSize;
        }
}
