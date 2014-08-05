import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

public class DeviceTFA {
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		

        String challenge = getAlpha();
//		  initialization();
//		  if (command.substring(0, 5).equals("Init,")) initialization();
//		  else 
//		  if (challenge.substring(0, 4).equals("TFA,")) 
        sendBeta(challenge.substring(4));
//		  String capitalizedSentence = sentence.toUpperCase();
//		  sendData = capitalizedSentence.getBytes();
//		  DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, receivePacket.getAddress(), receivePacket.getPort());
//		  socket.send(sendPacket);
//        }
	}

	public static String getAlpha() throws UnknownHostException,
			SocketException, IOException {
		byte[] receiveData = new byte[1024];
		InetAddress deviceAddr = InetAddress.getByName(Constants.DEVICEIP);
		DatagramSocket socket = new DatagramSocket(Constants.DEVICEPORT, deviceAddr);

//        while(true) {
		  DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
		  socket.receive(receivePacket);
		  String challenge = new String(receivePacket.getData());
		  System.out.println("Command received From the Client Server: " + challenge);
		  socket.close();
		return challenge;
	}

	private static void sendBeta(String alpha) throws IOException {	
		ECCurve curve = getCurve(Constants.CURVE_NAME);
		org.bouncycastle.math.ec.ECPoint ecPoint = decodePoint(curve, alpha);
		if (GroupG.pointMember(curve, ecPoint)) {
			String betaStr = FOPRF.OPRF_Encode(new BigInteger(Constants.OPRF_KEY, 16), ecPoint);
			byte[] beta = betaStr.getBytes();

			DatagramSocket socket = new DatagramSocket();
		    InetAddress clientIPAddress = InetAddress.getByName(Constants.CLIENTIP);	    
		    
		    DatagramPacket sendPacket = new DatagramPacket(beta, beta.length, clientIPAddress, Constants.CLIENTPORT);
			socket.send(sendPacket);
			System.out.println("Sent wi");
			socket.close(); 
		} else  {
			System.out.println("point not on the curve");
		}
	}

	public static ECCurve getCurve(String curveName) {
		
		ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
		ECCurve curve = ecSpec.getCurve();
		return curve;
	}

	public static org.bouncycastle.math.ec.ECPoint decodePoint(ECCurve curve, String challenge) {
		String[] rcvdStr = challenge.split(",");
		BigInteger x = new BigInteger(rcvdStr[0], 16);
		BigInteger y = new BigInteger(rcvdStr[1], 16);
		
		java.security.spec.ECPoint ecPoint = new ECPoint(x, y);
		org.bouncycastle.math.ec.ECPoint ecNewPoint  = EC5Util.convertPoint(curve, ecPoint, false);
		return ecNewPoint;
	}

	/*
	private static void initialization() throws InvalidKeyException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, FileNotFoundException, IOException, InvalidKeySpecException {
//		SInit();
		KeyGen.createSenderKey();
		byte[] pi = getHexString(KeyGen.retrivePubKey("spubkey")); 
	    
		DatagramSocket socket = new DatagramSocket();
	    InetAddress clientIPAddress = InetAddress.getByName(CLIENTIP);	    
	    
	    DatagramPacket sendPacket = new DatagramPacket(pi, pi.length, clientIPAddress, CLIENTPORT);
		socket.send(sendPacket);
		
	    byte[] receiveData = new byte[4096];
	    DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
	    socket.receive(receivePacket);
	    String wi = new String(receivePacket.getData());
	    
	    FileOutputStream fos = new FileOutputStream("wi");
		fos.write(wi.getBytes());
		fos.close();
		
	    System.out.println("Vectors received from web client:" + wi);
		
		socket.close();	
	}
	*/
	
	private static byte[] getHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result.getBytes();
	}
}


