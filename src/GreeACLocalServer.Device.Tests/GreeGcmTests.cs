using System.Security.Cryptography;
using System.Text;
using GreeACLocalServer.Device.Services;

namespace GreeACLocalServer.Device.Tests;

public class GreeGcmTests
{
    [Fact]
    public void MatchesKnownCiphertextAndTag()
    {
        const string json = "{\"cid\":\"9424b8f2e5d1\", \"mac\":\"9424b8f2e5d1\",\"t\":\"bind\",\"uid\":0}";
        var (pack, tag) = GreeGcm.Encrypt(GreeGcm.GenericKey, json);
        Assert.Equal("Jtod3XIt89Lqss6DOHETBcp07NIAzgfkbQU3H+DJn/zDIm9Xi1M7f4yk9aCGHseEwf35XMKtIPQDq97Iev6J", pack);
        Assert.Equal("el26k1B0DOncUasy5pDrZw==", tag);
        Assert.Equal(json, GreeGcm.Decrypt(GreeGcm.GenericKey, pack, tag));
    }

    [Fact]
    public void RejectsTamperedTag()
    {
        var (pack, tag) = GreeGcm.Encrypt(GreeGcm.GenericKey, "hello");
        var bytes = Convert.FromBase64String(tag);
        bytes[0] ^= 1;
        Assert.Throws<AuthenticationTagMismatchException>(() => GreeGcm.Decrypt(GreeGcm.GenericKey, pack, Convert.ToBase64String(bytes)));
    }
}
