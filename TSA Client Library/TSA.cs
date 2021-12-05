using Org.BouncyCastle.Tsp;
using System.Reflection;

namespace wan24.TSAClient
{
    /// <summary>
    /// High level RFC 3161 TSA client helper methods (<seealso href="https://github.com/clairernovotny/BouncyCastle-PCL">BouncyCastle-PCL</seealso> wrapper)
    /// These helper methods support a third party SaaS TSA like <seealso href="https://freetsa.org">freeTSA.org</seealso>.
    /// Find a list of free TSA servers at <seealso href="https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710">GitHub</seealso>.
    /// Find this open source project at <seealso href="https://github.com/nd1012/TSA-Client">GitHub</seealso>.
    /// Find an online developer reference at <seealso href="https://nd1012.github.io/TSA-Client/">GitHub</seealso>.
    /// <example>
    /// Some usage examples:
    /// <code>
    /// using wan24.TSAClient;
    /// 
    /// // Create a TSQ (using SHA512 and including the signer certificates)
    /// byte[] tsq = TSA.CreateRequest("source.file");
    /// 
    /// // Request the TSR
    /// byte[] tsr = TSA.SendRequest(tsq, "https://freetsa.org/tsr");
    /// 
    /// // Validate the TSR
    /// TSA.ValidateResponse(tsq, tsr);
    /// 
    /// // Validate the source data
    /// TSA.ValidateSourceTsr("source.file", tsr);
    /// 
    /// // Extract the timestamp token
    /// byte[] token = TSA.ExtractToken(tsr);
    /// 
    /// // Validate the source data using the timestamp token
    /// TSA.ValidateSourceToken("source.file", token);
    /// 
    /// // Validate the timestamp token using the X509 signer certificate
    /// TSA.ValidateToken(token, "/path/to/signer.crt");
    /// 
    /// // Get object information
    /// foreach(string info in TSA.RequestInfo(tsq))
    ///     Console.WriteLine($"TSQ: {info}");
    /// foreach(string info in TSA.ResponseInfo(tsr))
    ///     Console.WriteLine($"TSR: {info}");
    /// foreach(string info in TSA.TokenInfo(token))
    ///     Console.WriteLine($"Timestamp token: {info}");
    /// </code>
    /// </example>
    /// </summary>
    public static partial class TSA
    {
        /// <summary>
        /// BouncyCastle-PCL version information
        /// </summary>
        private static string _BC_VERSION = null;

        /// <summary>
        /// Get the TSA Client library version information
        /// </summary>
        public static string VERSION => Properties.Resources.VERSION;

        /// <summary>
        /// BouncyCastle-PCL version information
        /// </summary>
        public static string BC_VERSION =>
            _BC_VERSION ?? (_BC_VERSION = typeof(TimeStampToken).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>().InformationalVersion);
   }
}
