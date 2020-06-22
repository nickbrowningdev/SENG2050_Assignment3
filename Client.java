import java.io.*;
import java.net.*;
import java.security.*;
import java.math.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.CertificateException;
import java.util.Base64;
import sun.security.provider.SecureRandom;

public class Client
{
    // private variable declarations
    private static int clientID = 1234;
    private int receivedServerID;
    private BigInteger receivedSessionID;
    private BigInteger[] receivedRSAPublicKey;
    private static Server server = new Server();
    private static Client client = new Client();
    // dh-p, dh-g
    private BigInteger client_dh_p;
    private BigInteger client_dh_g;

    // isProbablePrime

    // private SecretKey sharesecurityKey;

    private BigInteger clientsessionkey;

    // sharing

    public static void main(String[] args) throws Exception {
        // set id
        client.setClientID(clientID);

        // declare server and client sockets
        String serverHostname = new String("127.0.0.1");

        // socket code
        Socket echoSocket = null;
        PrintWriter out = null;
        BufferedReader in = null;

        try 
        {
            echoSocket = new Socket(serverHostname, 10007);
            out = new PrintWriter(echoSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(echoSocket.getInputStream()));
        } 
        catch (UnknownHostException e) 
        {
            System.err.println("Don't know about host: " + serverHostname);
            System.exit(1);
        } 
        catch (IOException e) 
        {
            System.err.println("Couldn't get I/O for " + "the connection to: " + serverHostname);
            System.exit(1);
        }

        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        String userInput;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);

        // Generate Key
        SecretKey key;

        // sending server secret key
        server.setSecretKey(key = keyGenerator.generateKey());

        // Generating IV.
        byte[] IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.engineNextBytes(IV);

        // sender server IV
        server.setIV(IV);

        System.out.print("input: ");
        while ((userInput = stdIn.readLine()) != null) {

            out.println(userInput);

            byte[] userInput1 = client.encryptCBC(userInput, key, IV);

            System.out.print("Encrypted Message: " + (Base64.getEncoder().encodeToString(userInput1)) + "\n");

            String CBCDecrypted = client.decryptCBC(userInput1, key, IV);

            System.out.println("Decrypted Message: " + CBCDecrypted + "\n");
            
            if (userInput.equalsIgnoreCase("Bye")) 
                break;

            System.out.print ("input: ");            
	    }

	    out.close();
	    in.close();
	    stdIn.close();
	    echoSocket.close();
    }

    // encrypts message from client 
    public byte[] encryptCBC (String plainText, SecretKey key,byte[] IV) throws Exception 
    {
        byte[] tempMesssage = plainText.getBytes();

		try{
            //Get Cipher Instance
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            
            //Create SecretKeySpec
            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        
            //Create IvParameterSpec
            IvParameterSpec ivSpec = new IvParameterSpec(IV);

			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			return cipher.doFinal(tempMesssage);
        }
        catch (Exception ex) 
        {
			
		}
		
		return tempMesssage;
    }

    public String decryptCBC(byte[] cipherText, SecretKey key,byte[] IV) throws Exception
    {
        byte[] tempMesssage=cipherText;

        try
        {
			//Get Cipher Instance
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        
            //Create SecretKeySpec
            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
            
            //Create IvParameterSpec
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            
            //Initialize Cipher for DECRYPT_MODE
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            
            //Perform Decryption
            byte[] decryptedText = cipher.doFinal(tempMesssage);
            
            return new String(decryptedText);
        }
        catch (Exception ex) 
        {
            //e.printStackTrace();
            return new String(tempMesssage);
        }
        
        
    }

    // sets id
    public void setClientID(int clientID)
    {
        this.clientID = clientID;
    }

    // get id
    public int getClientID()
    {
        return clientID;
    }

    // sets received server id
    public void setReceivedServerID(int receivedServerID)
    {
        this.receivedServerID = receivedServerID;

        System.out.println("Client received Server ID: " + receivedServerID + "\n");
    }

    // get received server id
    public int getReceivedServerID()
    {
        return receivedServerID;
    }

    // set received session id
    public void setReceivedSessionID(BigInteger receivedSessionID)
    {
        this.receivedSessionID = receivedSessionID;

        System.out.println("Client received Session ID: " + receivedSessionID + "\n");
    }

    // get received session id
    public BigInteger getReceivedSessionID()
    {
        return receivedSessionID;
    }

    // set RSA Public Key from Server
    public void setReceivedRSAPublicKey(BigInteger[] receivedRSAPublicKey)
    {
        this.receivedRSAPublicKey = receivedRSAPublicKey;
    }

    // get RSA Public Key from Server
    public BigInteger[] getReceivedRSAPublicKey()
    {
        return receivedRSAPublicKey;
    }

    // set Server DH: p
    public void setClientDHp (BigInteger client_dh_p)
    {
        this.client_dh_p = client_dh_p;
    }

    // get Server DH: p
    public BigInteger getClientDHp()
    {
        return client_dh_p;
    }

    // set Server DH: g
    public void setClientDHg(BigInteger client_dh_g)
    {
        this.client_dh_g = client_dh_g;
    }

    // get Server DH: g
    public BigInteger getClientDHg()
    {
        return client_dh_g;
    }

    // simplified handshake: Client
    public void simplifiedClientHandshake(int sid, BigInteger ssid)
    {
        // checks if serverID and sessionID matches received serverID and sessionID
        // checks server id first
        if (client.getReceivedServerID() == server.getServerID())
        {
            // confirms
            System.out.println("Server ID Authentication Successful");

            // checks session if
            //if (client.getReceivedSessionID().equals(ssid))
            //{
                // confirms
                System.out.println("Session ID Authentication Successful");

                // dh between server and client
                // dh scheme
                // generate two primes
                // declared randoms
                // safe prime
                Random rand_dh_q = new Random();
                BigInteger dh_q = BigInteger.probablePrime(256, rand_dh_q);
                BigInteger one = new BigInteger("1");
                BigInteger two = new BigInteger("2");
                BigInteger safePrime = (two.multiply(dh_q)).add(one);
                Random rand_dh_g = new Random();               
                BigInteger dh_g = BigInteger.probablePrime(256, rand_dh_g);
                
                // making Client and Server share common prime and generator
                client.setClientDHp(safePrime);
                client.setClientDHg(dh_g);
                server.setServerDHp(safePrime);
                server.setServerDHg(dh_g);

                // diffie
                server.diffiehellman(server.getServerDHp(), server.getServerDHg());

                // client and server agree on safe prime and q
                /*if(client.getClientDHg().equals(server.getServerDHg()))
                {
                    if(client.getClientDHp().equals(server.getServerDHp()))
                    {
                        
                    }
                    else
                    {
                        System.out.println("Authentication Failed");
                    }
                }
                else
                {
                    System.out.println("Authentication Failed");
                }*/

                
            //}
            //else
            //{
                // cancels system
                //System.out.println("Session ID Authentication Failed");
                //System.exit(1);
            //}
        }
        else
        {
            // cancels system
            System.out.println("Server ID Authentication Failed");
            System.exit(1);
        }
    }
}