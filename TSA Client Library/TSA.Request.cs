using Org.BouncyCastle.Tsp;
using System;
using System.IO;
using System.Net;

namespace wan24.TSAClient
{
    // TSQ methods
    public static partial class TSA
    {
        /// <summary>
        /// Create a TSQ
        /// </summary>
        /// <param name="hash">SHA hash</param>
        /// <param name="outFile">Target filename</param>
        /// <param name="includeCert">Include signer certificates?</param>
        /// <returns>TSQ</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        /// <exception cref="ArgumentException">Unsupported SHA hash length</exception>
        public static byte[] CreateRequest(byte[] hash, string outFile = null, bool includeCert = true)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            string algorithm;
            switch (hash.Length)
            {
                case HASH_SHA1_LEN: algorithm = TspAlgorithms.Sha1; break;
                case HASH_SHA256_LEN: algorithm = TspAlgorithms.Sha256; break;
                case HASH_SHA384_LEN: algorithm = TspAlgorithms.Sha384; break;
                case HASH_SHA512_LEN: algorithm = TspAlgorithms.Sha512; break;
                default: throw new ArgumentException("Unsupported hash length", nameof(hash));
            }
            TimeStampRequestGenerator tsqg = new TimeStampRequestGenerator();
            tsqg.SetCertReq(includeCert);
            TimeStampRequest tsq = tsqg.Generate(algorithm, hash);
            byte[] data = tsq.GetEncoded();
            if (outFile == null) return data;
            if (File.Exists(outFile)) File.Delete(outFile);
            using (Stream fs = File.OpenWrite(outFile))
                fs.Write(data, 0, data.Length);
            return data;
        }

        /// <summary>
        /// Send a TSQ (receive a TSR)
        /// </summary>
        /// <param name="tsqFile">TSQ filename</param>
        /// <param name="uri">TSA URI (f.e. <c>https://freetsa.org/tsr</c>)</param>
        /// <param name="outFile">Target filename</param>
        /// <returns>TSR</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static byte[] SendRequest(string tsqFile, string uri, string outFile = null)
        {
            if (tsqFile == null) throw new ArgumentNullException(nameof(tsqFile));
            if (uri == null) throw new ArgumentNullException(nameof(uri));
            return SendRequest(File.ReadAllBytes(tsqFile), uri, outFile);
        }

        /// <summary>
        /// Send a TSQ (receive a TSR)
        /// <example>
        /// Using a custom request object in <paramref name="req"/>:
        /// <code>
        /// // Request the TSR with a custom request object
        /// using System.Net;
        /// HttpWebRequest req = (HttpWebRequest)WebRequest.Create("https://freetsa.org/tsr");
        /// // Configure req here...
        /// byte[] tsr = TSA.SendRequest(tsq, uri: null, req: req);
        /// </code>
        /// </example>
        /// </summary>
        /// <param name="tsq">TSQ</param>
        /// <param name="uri">TSA URI (f.e. <c>https://freetsa.org/tsr</c>, or <see langword="null"/>, if <paramref name="req"/> is given)</param>
        /// <param name="outFile">Target filename</param>
        /// <param name="req">Custom request object</param>
        /// <returns>TSR</returns>
        /// <exception cref="ArgumentNullException">Required parameter is <see langword="null"/></exception>
        public static byte[] SendRequest(byte[] tsq, string uri, string outFile = null, HttpWebRequest req = null)
        {
            if (tsq == null) throw new ArgumentNullException(nameof(tsq));
            if (req == null) req = (HttpWebRequest)WebRequest.Create(uri ?? throw new ArgumentNullException(nameof(uri)));
            req.Method = "POST";
            req.ContentType = "application/timestamp-query";
            req.ContentLength = tsq.Length;
            if (outFile != null && File.Exists(outFile)) File.Delete(outFile);
            using (Stream rs = req.GetRequestStream())
                rs.Write(tsq, 0, tsq.Length);
            using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
            using (Stream rs = new BufferedStream(res.GetResponseStream()))
            using (MemoryStream ms = new MemoryStream())
            using (Stream fs = outFile == null ? null : File.OpenWrite(outFile))
            {
                rs.CopyTo(ms);
                if (fs == null) return ms.ToArray();
                ms.Position = 0;
                ms.CopyTo(fs);
                return ms.ToArray();
            }
        }
    }
}
