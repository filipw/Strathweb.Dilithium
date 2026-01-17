namespace Strathweb.Dilithium.IdentityModel;

public interface IPqcBackend
{
    string Name { get; }
    
    (byte[] publicKey, byte[] privateKey) GenerateKeyPair(string algorithm);
    
    byte[] Sign(string algorithm, byte[] data, byte[] privateKey);
    
    bool Verify(string algorithm, byte[] data, byte[] signature, byte[] publicKey);
}
