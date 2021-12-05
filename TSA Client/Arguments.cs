namespace wan24.TSAClient
{
    /// <summary>
    /// Arguments helper
    /// </summary>
    internal sealed class Arguments
    {
        /// <summary>
        /// Arguments data
        /// </summary>
        private readonly Dictionary<string, object?> Data = new();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="args">Arguments</param>
        public Arguments(string[] args)
        {
            if (args == null) throw new ArgumentNullException(nameof(args));
            string? key = null, value;// Current key and value
            for (int i = 0; i < args.Length; i++)
            {
                // Get key/value
                if (args[i].StartsWith("--"))
                {
                    // Key/value pair
                    key = args[i][2..];
                    if (i >= args.Length - 1) throw new InvalidDataException($"Missing value for \"{key}\"");
                    value = args[++i];
                }
                else if (args[i].StartsWith("-"))
                {
                    // Flag
                    key = args[i][1..];
                    value = null;
                }
                else
                {
                    // Multiple values
                    if (key == null) throw new InvalidDataException($"Invalid usage at argument #{i + 1}");
                    value = args[i];
                }
                // Store parameter value
                if (!Data.ContainsKey(key))
                {
                    // New parameter
                    Data[key] = value;
                }
                else if (Data[key] is List<string> values)
                {
                    // Extend existing value list
                    values.Add(value ?? throw new InvalidDataException($"Mixing up parameter types for \"{key}\""));
                }
                else
                {
                    // Convert existing value to value list
                    Data[key] = new List<string>()
                    {
                        Data[key] as string ?? throw new InvalidDataException($"Mixing up parameter types for \"{key}\""),
                        value ?? throw new InvalidDataException($"Mixing up parameter types for \"{key}\"")
                    };
                }
            }
        }

        /// <summary>
        /// Get a value
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>(First) value or <see langword="null"/> (if not contained) or an empty string (if the parameter was given as flag)</returns>
        public string? this[string key]
        {
            get
            {
                if (!Data.ContainsKey(key)) return null;
                if (Data[key] == null) return string.Empty;
                return (Data[key] is List<string> values ? values[0] : Data[key]) as string;
            }
        }

        /// <summary>
        /// Count
        /// </summary>
        public int Count => Data.Count;

        /// <summary>
        /// Keys
        /// </summary>
        public IEnumerable<string> Keys => Data.Keys.AsEnumerable();

        /// <summary>
        /// Determine if a parameter was given
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Given?</returns>
        public bool Contains(string key) => Data.ContainsKey(key);

        /// <summary>
        /// Determine if a flag was given
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Given?</returns>
        public bool HasFlag(string key) => Data.ContainsKey(key) && Data[key] == null;

        /// <summary>
        /// Get values of a parameter
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Values</returns>
        public List<string>? Values(string key) => Data.ContainsKey(key)
            ? Data[key] as List<string> ?? new List<string>() { Data[key] as string ?? throw new InvalidOperationException("Parameter type is flag (has no values)") }
            : null;
    }
}
