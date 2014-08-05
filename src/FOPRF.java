import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;


public class FOPRF {
	
	// subF_k(x) = H'(x)^k
	public static ECPoint subOPRF(BigInteger key, ECPoint point) {
		ECPoint multiplier = point.multiply(key);
		return multiplier;
	}
	
	// OPRF = F_k(x) = H(x, H'(x)^k)
	public static String OPRF_Encode(BigInteger key, ECPoint point) throws NoSuchAlgorithmException {
		
		// key = Constants.OPRF_KEY;
		
		//ecPoint = Constants.HASH_OF_PASSWORD 
		//curveName = Constants.CURVE_NAME
//		ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
//		ECCurve curve = ecSpec.getCurve(); 
//		ECFieldFp field = new ECFieldFp(((ECCurve.Fp)curve).getQ());
//		BigInteger fieldSize = BigInteger.valueOf(field.getFieldSize()); //size of field
		
//		Convert Curve
//		EllipticCurve jCurve = new EllipticCurve(field, ecSpec.getCurve().getA().toBigInteger(), ecSpec.getCurve().getB().toBigInteger());
	
//		BigInteger x = ecPoint.getAffineX();
//      BigInteger y = ecPoint.getAffineY();
        
//		EC5Util ecUtil = new EC5Util();
//		EllipticCurve jCurve = EC5Util.convertCurve(curve, null);
//		java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(jCurve, Hex.decode(point));
//		ECPoint ecNewPoint  = EC5Util.convertPoint(curve, ecPoint, false);
		ECPoint multiplier = point.multiply(key);
		
//		return Hex.encode(multiplier.getEncoded());
		return Hash(encodePoint(point), encodePoint(multiplier));
	}

	private static String encodePoint(ECPoint point) {
		// TODO Auto-generated method stub
		BigInteger x = point.getAffineXCoord().toBigInteger();
		BigInteger y = point.getAffineYCoord().toBigInteger();
		String hexStrEncoding = x.toString(16).concat(",").concat(y.toString(16));
		return hexStrEncoding;
	}
	
	
	public static String Hash(String seed, String message) throws NoSuchAlgorithmException {
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		String x = message + seed;
		messageDigest.update(x.getBytes());
		return byteArray2Hex(messageDigest.digest());		
	}
	
	
	private static final char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	public static String byteArray2Hex(byte[] bytes) {
	    StringBuffer sb = new StringBuffer(bytes.length * 2);
	    for(final byte b : bytes) {
	        sb.append(hex[(b & 0xF0) >> 4]);
	        sb.append(hex[b & 0x0F]);
	    }
	    return sb.toString();
	}
	
//    private ECPoint multiply(ECPoint p, BigInteger k)
//    {
//        ECPoint q = p.getCurve().getInfinity();
//        int t = k.bitLength();
//        for (int i = 0; i < t; i++)
//        {
//            if (k.testBit(i))
//            {
//                q = q.add(p);
//            }
//            p = p.twice();
//        }
//        return q;
//    }
}
