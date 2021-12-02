namespace wan24.TSAClient
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            try
            {
                Console.WriteLine($"TSA Client version #{Properties.Resources.VERSION} (library version #{TSA.VERSION}, BouncyCastle-PCL {TSA.BC_VERSION})");
                // Interpret arguments
                Arguments ARGS = new(args);
                string? sourceFile = ARGS["file"];// Source filename
                string? hash = ARGS["hash"];// Source hash hex string
                byte[]? sourceHash = hash != null// Source hash
                    ? Enumerable.Range(0, hash.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hash.Substring(x, 2), 16))
                         .ToArray()
                    : null;
                string algorithm = ARGS.Contains("algo") ? ARGS["algo"] ?? throw new ArgumentException("Invalid parameter type for \"algo\"") : TSA.DEFAULT_HASH;// Hash algorithm
                string? tsqFile = ARGS["tsq"];// TSQ filename
                string? tsrFile = ARGS["tsr"];// TSR filename
                string? tokenFile = ARGS["token"];// Timestamp token filename
                string? certFile = ARGS["cert"];// Signer X509 certificate filename
                string? tsaUri = ARGS["tsa"];// TSA URI
                bool includeCert = !ARGS.HasFlag("nocert");// Don't include signer certificates in the TSR?
                bool validateSource = ARGS.HasFlag("validateSource");// Validate the source file/hash?
                bool newTsq = ARGS.HasFlag("newTsq");// Force creating a new TSQ?
                bool displayTsq = ARGS.HasFlag("tsqInfo");// Display TSQ information?
                bool displayTsr = ARGS.HasFlag("tsrInfo");// Display TSR information?
                bool displayToken = ARGS.HasFlag("tokenInfo");// Display timestamp token information?
                byte[]? tsq = null, tsr = null, token = null;// TSQ, TSR, timestamp token
                int done = 0;// Number of actions done
                bool help = ARGS.HasFlag("?") || ARGS.HasFlag("h") || ARGS.HasFlag("H") || ARGS.HasFlag("help");// Help requested?
                // Display help
                if (help)
                {
                    Console.WriteLine();
                    Console.WriteLine(Properties.Resources.HELP.Trim());
                    return 0;
                }
                // Determine if a hash needs to be created
                if (tsaUri != null && sourceHash == null)
                {
                    Console.WriteLine("Detected hash request");
                    if (sourceFile == null) throw new ArgumentException("Missing source file in parameter \"file\"");
                    Console.WriteLine($"Create {algorithm} hash from {sourceFile}");
                    sourceHash = TSA.CreateHash(sourceFile, algorithm);
                    Console.WriteLine($"Using {algorithm} hash {BitConverter.ToString(sourceHash).Replace("-", string.Empty)}");
                }
                // Create the TSR
                if (tsaUri != null)
                {
                    Console.WriteLine("Detected timestamp request");
                    if (tsqFile != null)
                    {
                        if (!newTsq && File.Exists(tsqFile))
                        {
                            Console.WriteLine($"Use existing TSQ from {tsqFile}");
                            tsq = File.ReadAllBytes(tsqFile);
                        }
                        else
                        {
                            Console.WriteLine($"Create TSQ to {tsqFile} (include certificates: {includeCert})");
                            tsq = TSA.CreateRequest(sourceHash, tsqFile, includeCert);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Create TSQ (include certificates: {includeCert})");
                        tsq = TSA.CreateRequest(sourceHash, includeCert: includeCert);
                    }
                    Console.WriteLine(tsrFile == null ? "Request TSR" : $"Create TSR to {tsrFile}");
                    tsr = TSA.SendRequest(tsq, tsaUri, tsrFile);
                    Console.WriteLine("Validate TSR");
                    TSA.ValidateResponse(tsq, tsr);
                    Console.WriteLine(tokenFile == null ? "Extract timestamp token" : $"Save timestamp token to {tokenFile}");
                    token = TSA.ExtractToken(tsr, tokenFile);
                    done++;
                }
                // Load a timestamp token
                if (token == null && tokenFile != null)
                {
                    Console.WriteLine($"Loading timestamp token from {tokenFile}");
                    token = File.ReadAllBytes(tokenFile);
                }
                // Validate the TSR
                if (tsaUri == null && tsrFile != null && tsqFile != null)
                {
                    Console.WriteLine("Detected TSR validation request");
                    Console.WriteLine($"Using TSR from {tsrFile}");
                    tsr = File.ReadAllBytes(tsrFile);
                    Console.WriteLine($"Using TSQ from {tsqFile}");
                    tsq = File.ReadAllBytes(tsqFile);
                    Console.WriteLine("Validate TSR");
                    TSA.ValidateResponse(tsq, tsr);
                    if (token == null)
                    {
                        Console.WriteLine(tokenFile == null ? "Extract timestamp token" : $"Save timestamp token to {tokenFile}");
                        token = TSA.ExtractToken(tsr, tokenFile);
                    }
                    done++;
                }
                // Extract the timestamp token
                if (tsaUri == null && tsrFile != null && tokenFile != null && tsqFile == null)
                {
                    Console.WriteLine("Detected timestamp token from TSR extraction request");
                    Console.WriteLine($"Using TSR from {tsrFile}");
                    tsr = File.ReadAllBytes(tsrFile);
                    Console.WriteLine($"Save timestamp token to {tokenFile}");
                    token = TSA.ExtractToken(tsr, tokenFile);
                    done++;
                }
                // Validate the source
                if (validateSource)
                {
                    Console.WriteLine("Detected source validation request");
                    if (sourceHash == null) throw new ArgumentException("Missing source filename in parameter \"file\" or source hash in parameter \"hash\"");
                    if (tsr == null)
                    {
                        if (tsrFile == null) throw new ArgumentException("Missing TSR filename in parameter \"tsr\"");
                        Console.WriteLine($"Validate source using TSR {tsrFile}");
                        TSA.ValidateSourceTsr(tsrFile, sourceHash);
                    }
                    else
                    {
                        Console.WriteLine("Validate source");
                        TSA.ValidateSourceTsr(tsr, sourceHash);
                    }
                    done++;
                }
                // Validate the timestamp token
                if (certFile != null)
                {
                    Console.WriteLine("Detected timestamp token validation request");
                    if (token == null) throw new ArgumentException("Missing timestamp token filename in parameter \"token\"");
                    Console.WriteLine($"Validate timestamp token using certificate {certFile}");
                    TSA.ValidateToken(token, certFile);
                    done++;
                }
                // Display TSQ information
                if (displayTsq)
                {
                    Console.WriteLine("Begin TSQ information:");
                    if (tsq != null)
                    {
                        foreach (string info in TSA.RequestInfo(tsq)) Console.WriteLine(info);
                    }
                    else if (tsqFile != null)
                    {
                        foreach (string info in TSA.RequestInfo(tsqFile)) Console.WriteLine(info);
                    }
                    else
                    {
                        throw new ArgumentException("Missing TSQ filename in parameter \"tsq\"");
                    }
                    Console.WriteLine("End TSQ information");
                    done++;
                }
                // Display TSR information
                if (displayTsr)
                {
                    Console.WriteLine("Begin TSR information:");
                    if (tsr != null)
                    {
                        foreach (string info in TSA.ResponseInfo(tsr)) Console.WriteLine(info);
                    }
                    else if (tsrFile != null)
                    {
                        foreach (string info in TSA.ResponseInfo(tsrFile)) Console.WriteLine(info);
                    }
                    else
                    {
                        throw new ArgumentException("Missing TSR filename in parameter \"tsr\"");
                    }
                    Console.WriteLine("End TSR information");
                    done++;
                }
                // Display timestamp token information
                if (displayToken)
                {
                    Console.WriteLine("Begin timestamp token information:");
                    if (token == null) throw new ArgumentException("Missing timestamp token filename in parameter \"token\"");
                    foreach (string info in TSA.TokenInfo(token)) Console.WriteLine(info);
                    Console.WriteLine("End timestamp token information");
                    done++;
                }
                // Display help
                if (done < 1)
                {
                    Console.Error.WriteLine("Nothing to do?!");
                    Console.WriteLine();
                    Console.WriteLine(Properties.Resources.HELP.Trim());
                    return 1;
                }
                Console.Error.WriteLine($"Done with {done} actions");
                return 0;
            }
            catch(ArgumentException ex)
            {
                // Invalid usage
                Console.Error.WriteLine(ex);
                return 1;
            }
            catch(InvalidDataException ex)
            {
                // Invalid data (f.e. validation failed)
                Console.Error.WriteLine(ex);
                return 2;
            }
            catch(Exception ex)
            {
                // Unknown error
                Console.Error.WriteLine(ex);
                return 99;
            }
        }
    }
}