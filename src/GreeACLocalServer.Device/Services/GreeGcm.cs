using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace GreeACLocalServer.Device.Services;

internal static class GreeGcm
{
    // Protocol constants from RobHofmann/HomeAssistant-GreeClimateComponent.
    // Fixed IV is a property of this proprietary protocol, NOT safe for new designs.
    public static readonly byte[] Nonce = Convert.FromHexString("5440784449675A516C5E6313");
    public static readonly byte[] AdditionalData = Encoding.ASCII.GetBytes("qualcomm-test");
    public static readonly byte[] GenericKey = Encoding.ASCII.GetBytes("{yxAHAY_Lm6pbC/<");

    public static (string Pack, string Tag) Encrypt(byte[] key, string plaintext)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 16) throw new ArgumentException("Gree GCM expects a 16-byte AES key.", nameof(key));
        byte[] plain = Encoding.UTF8.GetBytes(plaintext);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(Nonce, plain, cipher, tag, AdditionalData);
        return (Convert.ToBase64String(cipher), Convert.ToBase64String(tag));
    }

    public static string Decrypt(byte[] key, string pack, string tag)
    {
        if (key.Length != 16) throw new ArgumentException("Gree GCM expects a 16-byte AES key.", nameof(key));
        byte[] cipher = Convert.FromBase64String(pack);
        byte[] authTag = Convert.FromBase64String(tag);
        if (authTag.Length != 16) throw new CryptographicException("Invalid GCM authentication tag length.");
        byte[] plain = new byte[cipher.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(Nonce, cipher, authTag, plain, AdditionalData);
        return Encoding.UTF8.GetString(plain);
    }

    public static string CreateBindRequest(string mac)
    {
        mac = NormalizeMac(mac);
        // Keep inner JSON spacing identical to the Python reference; GCM authenticates bytes.
        string inner = $"{{\"cid\":\"{mac}\", \"mac\":\"{mac}\",\"t\":\"bind\",\"uid\":0}}";
        var (pack, tag) = Encrypt(GenericKey, inner);
        return JsonSerializer.Serialize(new { cid = "app", i = 1, pack, t = "pack", tcid = mac, uid = 0, tag });
    }

    public static string CreateRequest(string mac, byte[] deviceKey, string innerJson)
    {
        mac = NormalizeMac(mac);
        var (pack, tag) = Encrypt(deviceKey, innerJson);
        return JsonSerializer.Serialize(new { cid = "app", i = 0, pack, t = "pack", tcid = mac, uid = 0, tag });
    }

    public static string DecryptReply(byte[] key, string responseJson)
    {
        using var document = JsonDocument.Parse(responseJson);
        var root = document.RootElement;
        string pack = root.GetProperty("pack").GetString() ?? throw new FormatException("Missing pack");
        string tag = root.GetProperty("tag").GetString() ?? throw new FormatException("Missing tag");
        return Decrypt(key, pack, tag);
    }

    public static string NormalizeMac(string mac)
    {
        string normalized = mac.Replace(":", "").Replace("-", "").ToLowerInvariant();
        if (normalized.Length != 12 || !System.Text.RegularExpressions.Regex.IsMatch(normalized, "^[0-9a-f]{12}$"))
            throw new ArgumentException("MAC must be 12 hexadecimal digits.", nameof(mac));
        return normalized;
    }
}
