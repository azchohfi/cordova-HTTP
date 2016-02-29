using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Windows.Security.Cryptography.Certificates;
using Windows.Web.Http;

namespace CordovaHttpPlugin
{
    public sealed class CordovaHttpPlugin
    {
        public async void X()
        {
            // Send a get request to Bing
            var client = new HttpClient();
            var bingUri = new Uri("https://www.bing.com");
            var response = await client.GetAsync(bingUri);

            // Get the list of certificates that were used to validate the server's identity
            var serverCertificates = response.RequestMessage.TransportInformation.ServerIntermediateCertificates;

            // Perform validation
            if (!ValidCertificates(serverCertificates))
            {
                // Close connection as chain is not valid
                return;
            }

            Debug.WriteLine("Validation passed");
            // Validation passed, continue with connection to service
        }

        private static bool ValidCertificates(IReadOnlyList<Certificate> certs)
        {
            // In this example, we iterate through the certificates and check that the chain contains
            // one specific certificate we are expecting
            for (var i = 0; i < certs.Count; i++)
            {
                Debug.WriteLine("Cert# " + i + ": " + certs[i].Subject);
                var thumbprint = certs[i].GetHashValue();

                // Check if the thumbprint matches whatever you are expecting
                // ‎d4 de 20 d0 5e 66 fc 53 fe 1a 50 88 2c 78 db 28 52 ca e4 74
                byte[] expected = { 212, 222, 32, 208, 94, 102, 252, 83, 254, 26, 80, 136, 44, 120, 219, 40, 82, 202, 228, 116 };

                if (ThumbprintMatches(thumbprint, expected))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ThumbprintMatches(byte[] thumbprint, byte[] expected)
        {
            return thumbprint.SequenceEqual(expected);
        }
    }
}
