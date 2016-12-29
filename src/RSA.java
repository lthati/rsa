import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSA {
	
	private int bitLength = 1024;
	
	private Random rnd;
	
	BigInteger p, q, n, c, d;
	
	public RSA()
	{
		rnd = new Random();
	}

	public static long f(long a, long p, long q)
	{
		if(p==0)
		{
			return 1;
		}
		else if(p==1)
		{
			return a;
		}
		
		//if a ≥ q, then reduce a to (a mod q)
		if(a>=q)
		{
			a = a % q;
		}
		
		//if p is even, then a^p mod q = (a^2 mod q )p/2 mod q
		if(p % 2 == 0)
		{
			long b = a*a;
			p = p/2;
			return f(b,p,q);
		}
		//if p is odd, then a^p mod q = [a × (a^2 mod q )(p-1)/2 ] mod q;
		else
		{
			long b = a*a;
			p = (p-1)/2;
			return (a*f(b,p,q)) % q;
		}
	}
	
	public BigInteger primegen(int t)
	{
		BigInteger value = BigInteger.probablePrime(bitLength, rnd);
		int tries = 1;
		while(!value.isProbablePrime(1) && tries<=t)
		{
			value = BigInteger.probablePrime(bitLength, rnd);
			tries++;
		}
		return value;
	}
	
	public void keygen(BigInteger p, BigInteger q)
	{
		n = p.multiply(q);
		
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		
		c = phi.probablePrime(bitLength, rnd);
		
		while (phi.gcd(c).compareTo(BigInteger.ONE) > 0 && c.compareTo(phi) < 0)
        {
            c.add(BigInteger.ONE);
        }
		
		d = c.modInverse(phi);
	}
	
	public BigInteger encryption(BigInteger m, BigInteger c, BigInteger n)
	{
		return m.modPow(c, n);
	}
	
	public BigInteger decryption(BigInteger c, BigInteger d, BigInteger n)
	{
		return c.modPow(d, n);
	}
	
	public static void main(String[] args) throws Exception
	{
		Scanner scanner=new Scanner(System.in);
		
		System.out.println("Testing f(a, p, q) = ((a power p) mod q) module operation:");
		
		System.out.print("a = ");
		long text = scanner.nextLong();
		System.out.print("p = ");
		long prime = scanner.nextLong();
		System.out.print("q = ");
		long mod = scanner.nextLong();
		
		System.out.printf("f(%d, %d, %d) = "+f(text, prime, mod), text, prime, mod);
		
		System.out.println(); System.out.println();
		
		System.out.println("Testing RSA:");
		
		RSA rsa = new RSA();
		
		rsa.p = rsa.primegen(50);
		
		rsa.q = rsa.primegen(50);

		rsa.keygen(rsa.p, rsa.q);
		
		System.out.println("Generated keys: ");
		System.out.printf("p=%o%nq=%o%nn=%o%nc=%o%nd=%o%n",rsa.p,rsa.q,rsa.n,rsa.c,rsa.d);
		
		System.out.print("Please enter the message to send securely using RSA: ");
		Scanner in =new Scanner(System.in);
		
		String s =in.nextLine();
					
		System.out.println("Message in Bytes: "+ bytesToString(s.getBytes()));
		
		BigInteger message = new BigInteger(s.getBytes());
		
		BigInteger cipher = rsa.encryption(message, rsa.c, rsa.n);
		
		System.out.println("sending the cipher as: "+cipher);
		
		BigInteger decryptedValue = rsa.decryption(cipher, rsa.d, rsa.n);
		
		System.out.println("Decrypted cipher in Bytes: "+ bytesToString(decryptedValue.toByteArray()));
		
		System.out.println("Decrypted message: "+new String(decryptedValue.toByteArray()));

	}
	
	private static String bytesToString(byte[] encrypted)
    {
        String message = "";
        for (byte b : encrypted)
        {
        	message += Byte.toString(b);
        }
        return message;
    }
 
}
