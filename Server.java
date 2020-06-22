import java.io.*;
import java.net.*;
import java.security.*;
import java.math.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.CertificateException;
import java.security.spec.RSAPublicKeySpec;

import sun.security.provider.SecureRandom;

public class Server
{
    // isProbablePrime

    // private variable declarations
    // server id
    private int serverID;

    // session id
    private static BigInteger sessionID;

    // client id
    private int receivedClientID;

    // rsa public key
    private BigInteger[] RSAPublicKey;
    private BigInteger[] RSAPrivateKey;

    // dh keypair
    private KeyPair keyPairDH;

    // declared objects
    private static Client client = new Client();
    private static Server server = new Server();

    // declared primes
    private BigInteger p;
    private BigInteger q;

    // dh-p, dh-g
    private BigInteger server_dh_p;
    private BigInteger server_dh_g;

    // server session key
    private BigInteger serversessionkey;

    // shared session key
    private BigInteger sharedsessionkey;

    // hashed message
    private String hashedmessage;

    // rsa: n and d
    private BigInteger n;
    private BigInteger d;

    // digital signature
    private BigInteger digitalsignature;

    // iv 
    byte[] IV;

    // secret
    SecretKey secretKey;

    // nouce 
    IvParameterSpec nouce;

    // e
    BigInteger e;

    public static void main(String[] args) throws Exception 
    {

        // set ids
        server.setServerID(5678);

        // create session id
        sessionID = server.setSessionID(sessionID);

        // declare server socket
        ServerSocket serverSocket = null;

        // declare client socket
        Socket clientSocket = null;

        // socket code
        try {
            serverSocket = new ServerSocket(10007);
        } catch (IOException ex) {
            System.err.println("Could not listen on port: 10007.");
            System.exit(1);
        }

        System.out.println("Waiting for connection.....");

        try {
            // set_up_request: hello
            clientSocket = serverSocket.accept();

            // display client and server ids
            System.out.println("Server ID: " + server.getServerID());
            System.out.println("Client ID: " + client.getClientID());

            // display sessionID
            System.out.println("Session ID: " + server.getSessionID().toString());

            // rsa scheme
            // generate two primes
            // declared randoms
            Random rand_p = new Random();
            Random rand_q = new Random();

            // sets the primes
            BigInteger p_temp = BigInteger.probablePrime(2048, rand_p);
            BigInteger q_temp = BigInteger.probablePrime(2048, rand_q);

            // set p and q
            server.setP(p_temp);
            server.setQ(q_temp);

            // display p and q
            System.out.println("P: " + server.getP().toString() + "\n");
            System.out.println("Q: " + server.getQ().toString());

            // rsa key gen
            BigInteger[][] RSAKeys = rsaKeyGen(p_temp, q_temp);

            // get keys
            BigInteger[] RSAPublicKey = RSAKeys[0];
            BigInteger[] RSAPrivateKey = RSAKeys[1];

            // set RSA public and private keys
            server.setRSAPublicKey(RSAPublicKey);
            server.setRSAPrivateKey(RSAPrivateKey);

            // display that rsa keys were made
            System.out.println("RSA Public and Private Keys Made");

            // convert int to bigint
            BigInteger temp_serverID = new BigInteger("5678");
            BigInteger temp_clientID = new BigInteger("1234");

            // generate Server_Hello:
            BigInteger serverIDclientID = temp_serverID.add(temp_clientID);

            // generate and verify digital signature
            server.generateDigitalSignature(server.getRSAPublicKey(), server.getRSAPrivateKey(), serverIDclientID);
            server.verifyDigitalSignature(server.getDigitalSignature(), server.getE(), server.getN());

            // setup: server's RSA public key
            client.setReceivedRSAPublicKey(server.getRSAPublicKey());
            System.out.println("Client Receives RSA Public Key");

            // receive client id from client
            server.setReceivedClientID(client.getClientID());
            
            // send client, server id and session id
            client.setReceivedServerID(server.getServerID());
            client.setReceivedSessionID(server.getSessionID());

            // start handshake between client and server
            server.simplifiedServerHandshake(server.getReceivedClientID());

        } catch (IOException ex) {
            System.err.println("Accept failed.");
            System.exit(1);
        }

        System.out.println("Connection successful");

        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        String inputLine;

        System.out.println("Waiting for input.....");

        byte[] nonceByte={0x0c, 0x04, 0x01, 0x07, 0x09, 0x03, 0x02, 0x0c};
        IvParameterSpec ivPS = new IvParameterSpec(nonceByte);
        server.setNouce(ivPS);

        SecretKey temp_key = server.getSecretKey();

        while ((inputLine = in.readLine()) != null) 
        {
            byte[] inputLine1 = server.encryptCTR(inputLine, temp_key, ivPS);

            System.out.println("Encrypted Message: " + (Base64.getEncoder().encodeToString(inputLine1)) + "\n");

            String CTRDecrypted = server.decryptCTR(inputLine1, server.getSecretKey(), ivPS);
            
            System.out.println("Decrypted: " + CTRDecrypted + "\n");
            out.println(inputLine);

            if (inputLine.equalsIgnoreCase("Bye"))
                break;
        }

        out.close();
        in.close();
        clientSocket.close();
        serverSocket.close();

    }

    public byte[] encryptCTR(String plainText, SecretKey key, IvParameterSpec ivPS) throws Exception
    {
        byte[] tempMesssage = plainText.getBytes();
		byte[] nonceCountByte=new byte[16];
		byte[] cipherByte=new byte[16];

        try
        {
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, key, ivPS);
			return cipher.doFinal(tempMesssage);
        }
        catch (Exception e) 
        {
			e.printStackTrace();
		}
		
		return tempMesssage;
    }

    public String decryptCTR(byte[] cipherText, SecretKey key, IvParameterSpec ivPS) throws Exception
    {
        byte[] tempMesssage=cipherText;

        try
        {
			Cipher cipher = Cipher.getInstance("DESede/CTR/NoPadding");
			//Initialize Cipher for DECRYPT_MODE
            cipher.init(Cipher.DECRYPT_MODE, key, ivPS);
            
            //Perform Decryption
            byte[] decryptedText = cipher.doFinal(tempMesssage);
            
            return new String(decryptedText);
        }
        catch (Exception e) 
        {
            // e.printStackTrace();
            return new String(tempMesssage);
		}

		
    }

    // rsa key gen
    // algorithim based on SENG2250 lecture slides
    public static BigInteger[][] rsaKeyGen(BigInteger p, BigInteger q)
    {
        BigInteger temp_n = p.multiply(q);

        // set n
        server.setN(temp_n);

        BigInteger m = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // finding d
        BigInteger temp_e = new BigInteger("65537");

        // set e
        server.setE(temp_e);

        BigInteger temp_m = m;
        BigInteger[] rxy = rsagenGCD(temp_e, temp_m);

        BigInteger r = rxy[0];
        BigInteger x = rxy[1];
        BigInteger y = rxy[2];

        // get d
        BigInteger temp_d = x;

        // set d
        server.setD(temp_d);

        // returns statement
        return new BigInteger[][] { { temp_n, temp_e }, { p, q, temp_d } };
    }

    // set e
    public void setE(BigInteger e)
    {
        this.e = e;
    }

    // get e
    public BigInteger getE()
    {
        return e;
    }

    // set n
    public void setN(BigInteger n)
    {
        this.n = n;
    }

    // set d
    public void setD(BigInteger d)
    {
        this.d = d;
    }

    // get n
    public BigInteger getN()
    {
        return n;
    }

    // get d
    public BigInteger getD()
    {
        return d;
    }

    // extension of rsa key gen
    // finds d
    public static BigInteger[] rsagenGCD(BigInteger e, BigInteger m)
    {
        if(m.equals(BigInteger.ZERO))
        {
            BigInteger x1 = BigInteger.ONE;
            BigInteger y1 = BigInteger.ZERO;
            BigInteger x = x1;
            BigInteger y = y1;
            BigInteger r = e;
            BigInteger[] result = {r, x, y};
            return result ;
        }
        else
        {
            BigInteger[] temp = rsagenGCD(m, e.mod(m));
            BigInteger r  = temp[0];
            BigInteger x1 = temp[1];
            BigInteger y1 = temp[2];

            BigInteger x = y1 ;
            BigInteger y = x1.subtract(e.divide(m).multiply(y1)) ;
            BigInteger[] result = {r, x, y} ;
            return result;
        }
    }

    // h(m)^d mod n
    public BigInteger generateDigitalSignature(BigInteger[] pubkey, BigInteger[] privatekey, BigInteger message)
    {
        BigInteger new_digitalsignature = null;

        try
        {
            /*String temp_hashedMessage = sha256(message);
            server.setHashMessage(temp_hashedMessage);
            
            BigInteger hashString = new BigInteger(temp_hashedMessage);*/
            BigInteger temp_digitalsignature = FastModExpo(message, server.getD(), server.getN());

            server.setDigitalSignature(temp_digitalsignature);

            new_digitalsignature = temp_digitalsignature;
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }

        return new_digitalsignature;
    }

    // set digital signature
    public void setDigitalSignature(BigInteger digitalsignature)
    {
        this.digitalsignature = digitalsignature;
    }

    // get digital signature
    public BigInteger getDigitalSignature()
    {
        return digitalsignature;
    }

    // create hashed message
    public static String sha256(BigInteger message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(((String) message.toString()).getBytes("UTF-8"));
            StringBuffer hexString = new StringBuffer();
    
            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
    
            return hexString.toString();
        } 
        catch(Exception ex)
        {
           throw new RuntimeException(ex);
        }
    }

    // sets hashed message
    public void setHashMessage(String hashedmessage)
    {
        this.hashedmessage = hashedmessage;
    }

    // gets hashed message
    public String getHashMessage(String hashedmessage)
    {
        return hashedmessage;
    }

    // h(m) = s^e mod n
    public void verifyDigitalSignature(BigInteger digitalsignature, BigInteger e, BigInteger n)
    {
        try
        {
            //String temp_hashmessage = server.getHashMessage(hashedmessage);

            //BigInteger isDigitalSignature = new BigInteger(temp_hashmessage);

            //isDigitalSignature = server.FastModExpo(digitalsignature, e, n);

            if(digitalsignature.equals(server.getDigitalSignature()))
            {
                System.out.println("Digital Signature Verified!");
            }
            else
            {
                // decline
                System.out.println("Digital Signature Doesn't Match");
                System.exit(1);
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }     
    }

    public BigInteger FastModExpo(BigInteger b, BigInteger e, BigInteger m)
    {
        BigInteger result = new BigInteger("1");
        BigInteger temp_compare = new BigInteger("1");
        BigInteger zero = new BigInteger("0");

        if (m.equals(temp_compare))
        {
            return result;
        }
        else //m.and(temp_compare)).equals(temp_compare)
        {
            while (e.intValue() > zero.intValue())
            {
                if ((e.intValue() & temp_compare.intValue()) == 1)
                {
                    result = (result.multiply(b)).mod(m);
                }
                
                e = e.shiftRight(1);
                b = (b.multiply(b)).mod(m);    
            }
            return result;
        }
    }

    // set id
    public void setServerID(int serverID)
    {
        this.serverID = serverID;
    }

    // get id
    public int getServerID()
    {
        return serverID;
    }

    // sets RSA Public Key
    public void setRSAPublicKey(BigInteger[] RSAPublicKey) {
        this.RSAPublicKey = RSAPublicKey;
    }

    // gets RSA Public Key
    public BigInteger[] getRSAPublicKey()
    {
        return RSAPublicKey;
    }

    // sets RSA Private Key
    public void setRSAPrivateKey(BigInteger[] RSAPrivateKey)
    {
        this.RSAPrivateKey = RSAPrivateKey;
    }

     // get RSA public key
     public BigInteger[] getRSAPrivateKey()
     {
         return RSAPrivateKey;
     }

    // sets received client ID
    public void setReceivedClientID(int receivedClientID)
    {
        this.receivedClientID = receivedClientID;

        System.out.println("Server received Client ID: " + receivedClientID + "\n");
    }

    // gets received client ID
    public int getReceivedClientID()
    {
        return receivedClientID;
    }  

    // sets session ID
    public BigInteger setSessionID(BigInteger sessionID)
    {
        // declare length and random
        final int LENGTH = 256;
        Random random = new Random();
        
        BigInteger p_temp = BigInteger.probablePrime(LENGTH, random);

        // returns session id
        return p_temp;
    }

    // gets session ID
    public BigInteger getSessionID()
    {
        return sessionID;
    }

    // set P
    public void setP(BigInteger p)
    {
        this.p = p;
    }

    // set Q
    public void setQ(BigInteger q)
    {
        this.q = q;
    }

    // get P
    public BigInteger getP()
    {
        return p;
    }

    // get Q
    public BigInteger getQ()
    {
        return q;
    }

    //	get DH Public Key
    public PublicKey getDHPublicKey()
    {
		return keyPairDH.getPublic();
	}

    // simplified handshake: Server
    public void simplifiedServerHandshake(int receivedClientID)
    {
        // checks if clientID matches received clientID
        if ((client.getClientID()) == (receivedClientID))
        {
            // confirms
            System.out.println("Client ID Authentication Successful");

            // checks session id and server id
            client.simplifiedClientHandshake(serverID, sessionID);
        }
        else
        {
            // cancels system
            System.out.println("Client ID Authentication Failed");
            System.exit(1);
        }
    }

    public void diffiehellman (BigInteger safePrime, BigInteger g)
    {
        // generate private key
        Random client_dh_pk = new Random(safePrime.intValue());
        Random server_dh_pk = new Random(safePrime.intValue());

        BigInteger ClientDHPrivateKey = new BigInteger(safePrime.bitLength(), client_dh_pk);
        BigInteger ServerDHPrivateKey = new BigInteger(safePrime.bitLength(), server_dh_pk);

        // creating public keys
        BigInteger ClientDHPublicKey = FastModExpo(g, ClientDHPrivateKey, safePrime);
        BigInteger ServerDHPublicKey = FastModExpo(g, ServerDHPrivateKey, safePrime);

        if (ClientDHPublicKey.equals(ServerDHPublicKey))
        {
            server.setSharedSessionKey(ClientDHPublicKey);
        }
        else
        {
            System.out.println("DH doesn't match");
            System.exit(1);
        }
    }

    // set Server DH: p
    public void setServerDHp (BigInteger server_dh_p)
    {
        this.server_dh_p = server_dh_p;
    }

    // get Server DH: p
    public BigInteger getServerDHp()
    {
        return server_dh_p;
    }

    // set Server DH: g
    public void setServerDHg(BigInteger server_dh_g)
    {
        this.server_dh_g = server_dh_g;
    }

    // get Server DH: g
    public BigInteger getServerDHg()
    {
        return server_dh_p;
    }

    // set server session key
    public void setServerSessionKey(BigInteger serversessionkey)
    {
        this.serversessionkey = serversessionkey;
    }

    // get server session key
    public BigInteger getServerSessionKey()
    {
        return serversessionkey;
    }

    // set shared session key
    public void setSharedSessionKey(BigInteger sharedsessionkey)
    {
        this.sharedsessionkey = sharedsessionkey;
    }

    // get shared session key
    public BigInteger getSharedSessionKey()
    {
        return sharedsessionkey;
    }

    public void setIV(byte[] IV)
    {
        this.IV = IV;
    }

    public byte[] getIV()
    {
        return IV;
    }

    public void setSecretKey(SecretKey secretKey)
    {
        this.secretKey = secretKey;
    }

    public SecretKey getSecretKey()
    {
        return secretKey;
    }

    public void setNouce(IvParameterSpec nouce)
    {
        this.nouce = nouce;
    }

    public IvParameterSpec getNouce()
    {
        return nouce;
    }
}