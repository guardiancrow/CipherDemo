/**
 * 暗号文伝送のやりとりを模したテストプログラムです
 * 
 * AliceとBobとCarolは同じ暗号機を持っています
 * この暗号機は仕組みは同じですが鍵が違います
 * 鍵はRSA暗号で秘密鍵と公開鍵が必要です
 * 
 * いまAliceとBobは秘密のやりとりをしようとしています
 * 暗号化は相手の公開鍵を使って行います
 * 復号化は自分の秘密鍵を使って行います
 * Carolは盗聴しても暗号の仕組みは理解していますが鍵（AliceとBobの秘密鍵）がないので
 * 暗号化されている電文を復号できずやりとりを理解できません
 */

import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import java.io.*;
import java.util.*;

class AliceWorker extends CipherWorker{
	public AliceWorker(){
		text = "Alice's secret words";
	}
}

class BobWorker extends CipherWorker{
	public BobWorker(){
		text = "Bob's secret words";
	}
}

class CarolWorker extends CipherWorker{
	public CarolWorker(){
		text = "Carol's secret words";
	}
}

/**
 *暗号化のやりとりをしようしている人たちが行うことが出来る共通動作（基底クラス）です
 */
class CipherWorker{
	public CipherWorker(){
		cip = new CipherUnit();
		cip.initialize();
	}
	
	/**
	 * 暗号化を行います。
	 * 実験のため、データを標準出力に出力しています。（本来は特に暗号化前の文字列は開示すべきではありません）
	 * @param pubkey 暗号化のための公開鍵
	 * @return 暗号化されたデータ
	 */
	public byte[] encrypt(PublicKey pubkey){
		System.out.println("[" + getClass().getName() + "]暗号化される文字列：");
		System.out.println(text);
		System.out.println("[" + getClass().getName() + "]暗号化されたデータ：");
		System.out.println(buildHexString(text.getBytes()));	
		return cip.encrypt(text.getBytes(), pubkey);
	}
	
	/**
	 * 復号化を行います
	 * 実験のため、データを標準出力に出力しています。（本来は特に復号された文字列は開示すべきではありません）
	 * @param source 暗号化されたデータ
	 */
	public void decrypt(byte[] source){
		byte [] dec = cip.decrypt(source);
		if(dec != null){
			System.out.println("[" + getClass().getName() + "]復号されたデータ：");
			System.out.println(buildHexString(dec));	
			System.out.println("[" + getClass().getName() + "]復号された文字列：");
			System.out.println(new String(dec));
		}
	}
	
	/**
	 * DER形式のRSA鍵を読み込みます。
	 * 秘密鍵はPKCS#8（PKCS8EncodedKeySpec）、公開鍵はX.509形式（X509EncodedKeySpecで直接読み込める形式）でなければなりません。
	 * @param prifilename 秘密鍵のファイル名
	 * @param pubfilename 公開鍵のファイル名
	 */
	public void loadKeyPair(String prifilename, String pubfilename){
		loadKeyPair(prifilename, pubfilename, false);
	}
	
	/**
	 * RSA鍵を読み込みます。
	 * 秘密鍵はPKCS#8（PKCS8EncodedKeySpec）、公開鍵はX.509形式（X509EncodedKeySpecで直接読み込める形式）でなければなりません。
	 * @param prifilename 秘密鍵のファイル名
	 * @param pubfilename 公開鍵のファイル名
	 * @param isPEMFormat 真の場合：PEM形式 偽の場合：DER形式
	 */
	public void loadKeyPair(String prifilename, String pubfilename, boolean isPEMFormat){
		cip.loadKeyPair(prifilename, pubfilename, isPEMFormat);
	}
	
	/**
	 * DER形式のRSA鍵を保存します
	 * @param prifilename 秘密鍵のファイル名
	 * @param pubfilename 公開鍵のファイル名
	 */
	public void saveKeyPair(String prifilename, String pubfilename){
		saveKeyPair(prifilename, pubfilename, false);
	}
	
	/**
	 * RSA鍵を保存します
	 * @param prifilename 秘密鍵のファイル名
	 * @param pubfilename 公開鍵のファイル名
	 * @param isPEMFormat 真の場合：PEM形式 偽の場合：DER形式
	 */
	public void saveKeyPair(String prifilename, String pubfilename, boolean isPEMFormat){
		cip.saveKeyPair(prifilename, pubfilename, isPEMFormat);
	}
	
	/**
	 * 公開鍵を通知します
	 * @return 現在保持している公開鍵
	 */
	public PublicKey getPublicKey(){
		return cip.pubkey;
	}
	
	/**
	 * 暗号化するテキストを変更します
	 * もちろん本来は外部から呼び出すべきではありませんね。
	 * @param str テキスト文
	 */
	public void setText(String str){
		text = str;
	}
	
	/**
	 * 16進数ダンプ用
	 * @param source ダンプしたいバイト列
	 * @return 文字列化されたバイト文字列
	 */
	private String buildHexString(byte[] source){
		StringBuffer buffer = new StringBuffer();
		for(byte b : source){
			buffer.append(String.format("%02X", b));
		}
		return buffer.toString();
	}
	
	protected CipherUnit cip;
	protected String text;
}

/**
 * 暗号機のクラスです
 */
class CipherUnit {
	public CipherUnit(){
		m_providerString = "RSA";
		pubkey = null;
		m_prikey = null;
	}
	
	/**
	 * 鍵を初期化します。ここで作成される鍵を使用せずに、
	 * 後でファイルに保存しているものを読み込みことも出来ます
	 */
	public void initialize(){
		try{
			KeyPairGenerator keygen = KeyPairGenerator.getInstance(m_providerString);
			SecureRandom random = new SecureRandom();
			keygen.initialize(2048, random);
			
			KeyPair keypair = keygen.generateKeyPair();
			pubkey = keypair.getPublic();
			m_prikey = keypair.getPrivate();		
		} catch (Exception ex){
			ex.printStackTrace();
		}
	}
	
	/**
	 * DER形式のRSA鍵を読み込みます。
	 * 秘密鍵はPKCS#8（PKCS8EncodedKeySpec）、公開鍵はX.509形式（X509EncodedKeySpecで直接読み込める形式）でなければなりません。
	 * @param prifilename 秘密鍵のファイル名
	 * @param pubfilename 公開鍵のファイル名
	 */
	public void loadKeyPair(String prifilename, String pubfilename){
		loadKeyPair(prifilename, pubfilename, false);
	}
	
	/**
	 * RSA鍵を読み込みます。
	 * 秘密鍵はPKCS#8（PKCS8EncodedKeySpec）、公開鍵はX.509形式（X509EncodedKeySpecで直接読み込める形式）でなければなりません。
	 * @param prifilename 秘密鍵のファイル名
	 * @param pubfilename 公開鍵のファイル名
	 * @param isPEMFormat 真の場合：PEM形式 偽の場合：DER形式
	 */
	public void loadKeyPair(String prifilename, String pubfilename, boolean isPEMFormat){
		KeyFileManager keyfile = new KeyFileManager();
		pubkey = keyfile.loadRSAPublicKey(pubfilename, isPEMFormat);
		m_prikey = keyfile.loadRSAPrivateKey(prifilename, isPEMFormat);
	}
	
	/**
	 * DER形式のRSA鍵を保存します
	 * @param prifilename 秘密鍵のファイル名
	 * @param pubfilename 公開鍵のファイル名
	 */
	public void saveKeyPair(String prifilename, String pubfilename){
		saveKeyPair(prifilename, pubfilename, false);
	}
	
	/**
	 * RSA鍵を保存します
	 * @param prifilename 秘密鍵のファイル名
	 * @param pubfilename 公開鍵のファイル名
	 * @param isPEMFormat 真の場合：PEM形式 偽の場合：DER形式
	 */
	public void saveKeyPair(String prifilename, String pubfilename, boolean isPEMFormat){
		KeyFileManager keyfile = new KeyFileManager();
		if(isPEMFormat){
			keyfile.savePEM(m_prikey, prifilename, true);
			keyfile.savePEM(pubkey, pubfilename, false);		
		}else{
			keyfile.saveDER(m_prikey, prifilename);
			keyfile.saveDER(pubkey, pubfilename);
		}
	}
	
	//public byte[] encrypt(byte[] source){
	//	return encrypt(source, pubkey);
	//}

	/**
	 * 暗号化を行います。
	 * @param source 暗号化するバイト列
	 * @param key 暗号化に使用する鍵
	 * @return 暗号化されたバイト列
	 */
	public byte[] encrypt(byte[] source, Key key){
		try{
			Cipher cipher = Cipher.getInstance(m_providerString);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(source);
		}catch (Exception ex){
			ex.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 現在クラスが保持している秘密鍵を使用して復号します
	 * @param source 暗号化されたバイト列
	 * @return 復号化されたバイト列
	 */
	public byte[] decrypt(byte[] source){
		return decrypt(source, m_prikey);
	}	
	
	/**
	 * 復号を行います。
	 * @param source 暗号化されたバイト列
	 * @param key 復号化に使用する鍵
	 * @return 復号化されたバイト列
	 */
	public byte[] decrypt(byte[] source, Key key){
		try{
			Cipher cipher = Cipher.getInstance(m_providerString);
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(source);			
		}catch (Exception ex){
			ex.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 暗号アルゴリズムを指定します。現時点ではRSAのみが有効です
	 */
	private String m_providerString;
	
	/**
	 * 現在保持している公開鍵です
	 */
	public PublicKey pubkey;
	
	/**
	 * 現在保持している秘密鍵です
	 */
	private PrivateKey m_prikey;
}

/**
 * ファイル形式の鍵の読み書きを行います
 * PEM形式とDER形式をサポートしています
 */
class KeyFileManager{
	public KeyFileManager(){
	}
	
	public PublicKey loadRSAPublicKey(String filename){
		return loadRSAPublicKey(filename, true);
	}
	
	public PrivateKey loadRSAPrivateKey(String filename){
		return loadRSAPrivateKey(filename, true);
	}
	
	public PublicKey loadRSAPublicKey(String filename, boolean isPEMFormat){
		try{
			byte[] decodeddata = null;
			if(isPEMFormat){
				decodeddata = getDERfromPEM(filename);
			}else{
				decodeddata = getDERformFile(filename);
			}
			return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodeddata));
		}catch(Exception ex){
			ex.printStackTrace();
		}
		return null;
	}
	
	public PrivateKey loadRSAPrivateKey(String filename, boolean isPEMFormat){
		try{
			byte[] decodeddata = null;
			if(isPEMFormat){
				decodeddata = getDERfromPEM(filename);
			}else{
				decodeddata = getDERformFile(filename);
			}
			return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodeddata));
		}catch(Exception ex){
			ex.printStackTrace();
		}
		return null;
	}
	
	private byte[] getDERformFile(String filename)	{
		try{
			FileInputStream fis = new FileInputStream(filename);
			BufferedInputStream bis = new BufferedInputStream(fis);
			byte[] data = new byte[fis.available()];
			bis.read(data);
			bis.close();
			return data;
		}catch(Exception ex){
			ex.printStackTrace();
		}
		return null;
	}
	
	/**
	 * PEM形式の鍵ファイルから鍵データ(= DER形式)を取得します
	 * 単純に-----BEGIN (PUBLIC|PRIVATE) KEY-----と
	 *       -----END (PUBLIC|PRIVATE) KEY-----  の間を
	 * 読み込みBASE64を解きます
	 * 戻り値はDER形式そのものですので、そのままKeySpecに渡すことができます
	 * @param filename 鍵ファイル名
	 * @return DER形式の鍵データ
	 */
	private byte[] getDERfromPEM(String filename){
		try{
			String line;
			StringBuffer buffer = new StringBuffer();
			BufferedReader br = new BufferedReader(new FileReader(filename));
			boolean isKeyData = false;
			while ((line = br.readLine()) != null){
				if(line.startsWith("-----BEGIN") && line.endsWith("KEY-----")){
					isKeyData = true;
				}else if(line.startsWith("-----END") && line.endsWith("KEY-----")){
					isKeyData = false;
					break;
				}else if(isKeyData){
					buffer.append(line);
				}
			}
			br.close();
			Base64.Decoder base64decoder = Base64.getDecoder();
			return base64decoder.decode(buffer.toString());		
		}catch(Exception ex){
			ex.printStackTrace();
		}
		return null;
	}
	
	public void saveDER(Key key, String filename){
		saveDER(key.getEncoded(), filename);
	}
	
	public void saveDER(byte[] data, String filename){
		try{
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filename));
			bos.write(data);
			bos.flush();
			bos.close();
		}catch (Exception ex){
			ex.printStackTrace();
		}
	}
	
	/**
	 * PEM形式の鍵ファイルを書き出します。
	 * @param key 書き出す鍵
	 * @param filename 出力するファイル名
	 * @param isPrivate 真の場合：秘密鍵 偽の場合：公開鍵
	 */
	public void savePEM(Key key, String filename, boolean isPrivate){
		savePEM(key.getEncoded(), filename, isPrivate);
	}
	
	public void savePEM(byte[] data, String filename, boolean isPrivate){
		try{
			Base64.Encoder base64encoder = Base64.getEncoder();
			byte[] encdata = base64encoder.encode(data);
			BufferedWriter bw = new BufferedWriter(new FileWriter(filename));
			if(isPrivate){
				bw.write("-----BEGIN PRIVATE KEY-----");
			}else{
				bw.write("-----BEGIN PUBLIC KEY-----");
			}
			bw.newLine();
			for(int i=0;i<encdata.length;i++){
				bw.write(encdata[i]);
				if(i%64 == 63){
					bw.newLine();
				}
			}
			bw.newLine();
			if(isPrivate){
				bw.write("-----END PRIVATE KEY-----");
			}else{
				bw.write("-----END PUBLIC KEY-----");
			}
			bw.flush();
			bw.close();
		}catch (Exception ex){
			ex.printStackTrace();
		}
	}
}

public class CipherDemo {
	private static String buildHexString(byte[] source){
		StringBuffer buffer = new StringBuffer();
		for(byte b : source){
			buffer.append(String.format("%02X", b));
		}
		return buffer.toString();
	}
	
	public static void main(String[] args) {
		/**
		 * 公開鍵暗号方式での通信経路上の位置にあたります
		 * この経路上に平文が流れていないことに注目してください
		 */
		System.out.println("Cipher Demo");
		System.out.print("\r\n-------------------------------------\r\n\r\n");
		
		AliceWorker alice = new AliceWorker();
		BobWorker bob = new BobWorker();
		//CarolWorker carol = new CarolWorker();
		
		System.out.println("Bob -> Alice");
		
		byte[] encBobText = bob.encrypt(alice.getPublicKey());
		System.out.println("[public]暗号化に使われる公開鍵：");
		System.out.println(alice.getPublicKey().toString());
		System.out.println("[public]暗号化されたデータ（経路上）：");
		System.out.println(buildHexString(encBobText));
		alice.decrypt(encBobText);
		//System.out.println("[public]キャロルは暗号文を手に入れても解読することが困難（解読できず例外が出る）：");
		//carol.decrypt(encBobText);
		
		System.out.print("\r\n-------------------------------------\r\n\r\n");
		System.out.println("Alice -> Bob");
		
		byte[] encAliceText = alice.encrypt(bob.getPublicKey());
		System.out.println("[public]暗号化に使われる公開鍵：");
		System.out.println(bob.getPublicKey().toString());
		System.out.println("[public]暗号化されたデータ：");
		System.out.println(buildHexString(encAliceText));
		bob.decrypt(encAliceText);
		//System.out.println("[public]キャロルは暗号文を手に入れても解読するが困難（解読できず例外が出る）：");
		//carol.decrypt(encAliceText);
		
		/**
		 * OpenSSLで作成した鍵の読み込み・保存と暗号・復号テスト
		 * 
		 * 鍵の作成方法(RFC3447 PKCS#1 = 暗号の規格　秘密鍵公開鍵両方含まれる)
		 * > openssl genrsa -out newkey.pem 1024
		 * 秘密鍵(RPC5208 PKCS#8)
		 * > openssl pkcs8 -topk8 -in newkey.pem -out newkey.key -nocrypt
		 * 公開鍵(PKCS#1から公開鍵要素(publicExponentとmodulus)のみを抽出)
		 * > openssl rsa -in newkey.pem -pubout -out newkey.pub
		 * 
		 * 拡張子はすべて.pemの方がいいかもしれません。.keyや.pubは仮のものです。
		 */
		System.out.print("\r\n-------------------------------------\r\n\r\n");
		System.out.println("OpenSSLの鍵の読み込み暗号復号テスト：");
		
		/**
		 * わかりやすいように暗号化する電文を変更してみます。もちろん実際には外部からこういうことはできません。テスト用です。
		 */
		String text = "この電文はOpenSSLで作成した鍵で暗号と復号をしました。使えてますか？";
		alice.setText(text);
		
		alice.loadKeyPair("alice.key", "alice.pub", true);
		bob.loadKeyPair("bob.key", "bob.pub", true);
		byte[] encbytes = alice.encrypt(bob.getPublicKey());
		System.out.println("[public]暗号化に使われる公開鍵：");
		System.out.println(alice.getPublicKey().toString());
		System.out.println("[public]暗号化されたデータ（経路上）：");
		System.out.println(buildHexString(encBobText));
		bob.decrypt(encbytes);
		
		alice.saveKeyPair("alice_save.key", "alice_save.pub", true);
		bob.saveKeyPair("bob_save.key", "bob_save.pub", true);
		alice.saveKeyPair("alice_save_der.key", "alice_save_der.pub", false);
		bob.saveKeyPair("bob_save_der.key", "bob_save_der.pub", false);
	}
}
